// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT

package observer

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DockerNames maps a Docker cgroup scope (systemd names container cgroups
// "docker-<64hex-id>.scope") to the friendly container name, by polling the
// Docker Engine socket. Without it Hubble shows "docker-<hash>" as the app;
// with it the node reads "docker/<name>" (e.g. docker/hubble-ui). Best-effort:
// if the socket is absent or unreadable the resolver is a no-op and the raw
// scope name is kept.
type DockerNames struct {
	mu     sync.RWMutex
	m      map[string]string // full container id -> name
	client *http.Client
}

// NewDockerNames starts a resolver polling /run/docker.sock every 15s.
func NewDockerNames() *DockerNames {
	d := &DockerNames{
		m: map[string]string{},
		client: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", "/run/docker.sock")
				},
			},
		},
	}
	go d.loop()
	return d
}

func (d *DockerNames) loop() {
	for {
		d.refresh()
		time.Sleep(15 * time.Second)
	}
}

func (d *DockerNames) refresh() {
	resp, err := d.client.Get("http://docker/containers/json")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var cs []struct {
		Id    string
		Names []string
	}
	if err := json.NewDecoder(resp.Body).Decode(&cs); err != nil {
		return
	}
	m := make(map[string]string, len(cs))
	for _, c := range cs {
		if len(c.Names) > 0 {
			if name := strings.TrimPrefix(c.Names[0], "/"); name != "" {
				m[c.Id] = name
			}
		}
	}
	d.mu.Lock()
	d.m = m
	d.mu.Unlock()
}

// Resolve maps a systemd unit "docker-<id>.scope" to "docker/<name>" when the
// container is known; otherwise it returns unit unchanged.
func (d *DockerNames) Resolve(unit string) string {
	if !strings.HasPrefix(unit, "docker-") || !strings.HasSuffix(unit, ".scope") {
		return unit
	}
	id := strings.TrimSuffix(strings.TrimPrefix(unit, "docker-"), ".scope")
	d.mu.RLock()
	name := d.m[id]
	d.mu.RUnlock()
	if name != "" {
		return "docker/" + name
	}
	return unit
}
