// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT

package identity

import (
	"errors"
	"io/fs"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Watcher reports cgroup creations and deletions through a debounced
// channel. Two goroutines collaborate:
//
//   - readLoop is a tight inotify drain that pushes raw notifications
//     onto a buffered internal channel.
//   - debounceLoop coalesces those notifications: a burst of cgroup
//     events (e.g. a user login) becomes one wake-up after a configurable
//     quiet period.
//
// We watch every directory below /sys/fs/cgroup with IN_CREATE,
// IN_DELETE, IN_MOVED_FROM and IN_MOVED_TO so any structural change is
// surfaced. New directories get their own watch installed inline.
type Watcher struct {
	fd       int
	wdToPath sync.Map // int -> string
	pathToWd sync.Map // string -> int
	stop     chan struct{}
	log      *slog.Logger
	debounce time.Duration

	// subs holds one channel per Subscribe() caller. Multiple
	// independent consumers (the unit cache, the policy syncer, ...)
	// must each receive every wake-up — a single shared channel would
	// race them and one of the two would silently miss events.
	subsMu sync.Mutex
	subs   []chan struct{}
}

func NewWatcher(log *slog.Logger, debounce time.Duration) (*Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		fd:       fd,
		stop:     make(chan struct{}),
		log:      log,
		debounce: debounce,
	}

	if err := filepath.WalkDir(cgroupRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			w.addWatch(p)
		}
		return nil
	}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	raw := make(chan struct{}, 256)
	go w.readLoop(raw)
	go w.debounceLoop(raw)
	return w, nil
}

func (w *Watcher) addWatch(path string) {
	wd, err := unix.InotifyAddWatch(w.fd, path,
		unix.IN_CREATE|unix.IN_DELETE|unix.IN_MOVED_FROM|unix.IN_MOVED_TO)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) {
			w.log.Debug("inotify add", "path", path, "err", err)
		}
		return
	}
	w.wdToPath.Store(wd, path)
	w.pathToWd.Store(path, wd)
}

func (w *Watcher) removeWatch(path string) {
	v, ok := w.pathToWd.LoadAndDelete(path)
	if !ok {
		return
	}
	wd := v.(int)
	w.wdToPath.Delete(wd)
	_, _ = unix.InotifyRmWatch(w.fd, uint32(wd))
}

// Subscribe returns a fresh receive-only channel that fires once per
// debounced wake-up. Each subscriber gets its own channel; the
// broadcast inside debounceLoop fans out to all of them.
//
// Backward-compatible alias `Events` returns one such channel; new
// code should call Subscribe directly so it's clear there can be
// many consumers.
func (w *Watcher) Subscribe() <-chan struct{} {
	ch := make(chan struct{}, 1)
	w.subsMu.Lock()
	w.subs = append(w.subs, ch)
	w.subsMu.Unlock()
	return ch
}

// Events is a thin wrapper kept for callers that only need a single
// subscription. Equivalent to Subscribe().
func (w *Watcher) Events() <-chan struct{} { return w.Subscribe() }

// broadcast performs a non-blocking send on every registered
// subscriber channel. A slow subscriber doesn't back-pressure the
// others; it just misses this round.
func (w *Watcher) broadcast() {
	w.subsMu.Lock()
	subs := append([]chan struct{}(nil), w.subs...)
	w.subsMu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (w *Watcher) Close() error {
	close(w.stop)
	return unix.Close(w.fd) // unblocks readLoop with EBADF
}

// readLoop is a pure inotify drain. It blocks in Read; closing the fd
// from Close() breaks it out with EBADF.
func (w *Watcher) readLoop(raw chan<- struct{}) {
	buf := make([]byte, 64*1024)
	for {
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return
			}
			w.log.Debug("inotify read", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if n < unix.SizeofInotifyEvent {
			continue
		}

		off := 0
		notify := false
		for off+unix.SizeofInotifyEvent <= n {
			raw := (*unix.InotifyEvent)(unsafePointer(&buf[off]))
			nameLen := int(raw.Len)
			off += unix.SizeofInotifyEvent

			var name string
			if nameLen > 0 {
				end := off + nameLen
				if end > n {
					break
				}
				b := buf[off:end]
				for i, c := range b {
					if c == 0 {
						b = b[:i]
						break
					}
				}
				name = string(b)
				off = end
			}

			if raw.Mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 && raw.Mask&unix.IN_ISDIR != 0 {
				if v, ok := w.wdToPath.Load(int(raw.Wd)); ok {
					w.addWatch(filepath.Join(v.(string), name))
				}
				notify = true
			}
			if raw.Mask&(unix.IN_DELETE|unix.IN_MOVED_FROM) != 0 && raw.Mask&unix.IN_ISDIR != 0 {
				if v, ok := w.wdToPath.Load(int(raw.Wd)); ok {
					w.removeWatch(filepath.Join(v.(string), name))
				}
				notify = true
			}
			if raw.Mask&unix.IN_IGNORED != 0 {
				if v, ok := w.wdToPath.LoadAndDelete(int(raw.Wd)); ok {
					w.pathToWd.Delete(v.(string))
				}
			}
		}
		if notify {
			select {
			case raw <- struct{}{}:
			default: // already pending; debouncer will collapse
			}
		}
	}
}

// debounceLoop coalesces raw notifications into one wake-up per quiet
// period.
func (w *Watcher) debounceLoop(raw <-chan struct{}) {
	t := time.NewTimer(time.Hour)
	t.Stop()
	pending := false
	for {
		select {
		case <-w.stop:
			return
		case <-raw:
			pending = true
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			t.Reset(w.debounce)
		case <-t.C:
			if pending {
				pending = false
				w.broadcast()
			}
		}
	}
}
