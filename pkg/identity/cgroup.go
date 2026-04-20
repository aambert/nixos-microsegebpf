// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT

// Package identity resolves cgroupv2 paths to numeric cgroup IDs (the
// inode of the cgroup directory) and back to systemd unit names.
//
// The kernel exposes the cgroup ID via bpf_get_current_cgroup_id() in
// eBPF; in userspace it is simply the inode number of the corresponding
// directory under /sys/fs/cgroup. Walking the tree once gives us the
// full inverse mapping needed by the policy resolver.
package identity

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
)

const cgroupRoot = "/sys/fs/cgroup"

// Cgroup describes one cgroupv2 directory.
type Cgroup struct {
	ID          uint64 // inode number — matches bpf_get_current_cgroup_id()
	Path        string // full path under cgroupRoot, e.g. "/system.slice/firefox.service"
	SystemdUnit string // resolved unit name, "" for non-systemd cgroups
}

// Snapshot walks the cgroupv2 tree and returns every cgroup with its ID
// and (when applicable) its systemd unit name. This is cheap on a
// workstation (~hundreds of cgroups) and sidesteps the need to keep a
// long-lived inotify watch for the PoC.
func Snapshot() ([]Cgroup, error) {
	var out []Cgroup
	err := filepath.WalkDir(cgroupRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable subtrees rather than abort
		}
		if !d.IsDir() {
			return nil
		}
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			return nil
		}
		rel := strings.TrimPrefix(p, cgroupRoot)
		if rel == "" {
			rel = "/"
		}
		out = append(out, Cgroup{
			ID:          st.Ino,
			Path:        rel,
			SystemdUnit: unitFromPath(rel),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk cgroupfs: %w", err)
	}
	return out, nil
}

// unitFromPath returns the systemd unit name encoded in a cgroupv2 path.
// systemd uses the convention "<slice>/<unit>" where the unit segment
// ends in .service, .scope, .socket, etc.
//
// Examples:
//
//	/system.slice/sshd.service                              -> sshd.service
//	/user.slice/user-1000.slice/app.slice/firefox.service   -> firefox.service
//	/user.slice/user-1000.slice/session-3.scope             -> session-3.scope
//	/                                                       -> ""
func unitFromPath(p string) string {
	if p == "/" {
		return ""
	}
	last := filepath.Base(p)
	for _, suf := range []string{".service", ".scope", ".socket", ".mount", ".timer"} {
		if strings.HasSuffix(last, suf) {
			return last
		}
	}
	return ""
}

// MatchUnitGlob returns true if `unit` matches a shell-style glob (`*`
// only). Empty pattern matches nothing.
func MatchUnitGlob(pattern, unit string) bool {
	if pattern == "" || unit == "" {
		return false
	}
	ok, _ := filepath.Match(pattern, unit)
	return ok
}

// MatchPathPrefix returns true if `path` is `prefix` or starts with
// `prefix + "/"`.
func MatchPathPrefix(prefix, path string) bool {
	if prefix == "" || path == "" {
		return false
	}
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, strings.TrimRight(prefix, "/")+"/")
}
