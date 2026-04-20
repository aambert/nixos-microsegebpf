# SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
# SPDX-License-Identifier: MIT

GO         ?= go
BPF2GO_OUT := bpf
AGENT      := microseg-agent

.PHONY: all generate build clean run test vmsync vmbuild vmrun

all: build

# Generate vmlinux.h from the running kernel's BTF — keeps the build
# kernel-agnostic (CO-RE) without shipping a copy in-tree.
$(BPF2GO_OUT)/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Run bpf2go: compile bpf/microseg.c to bytecode and generate Go bindings.
generate: $(BPF2GO_OUT)/vmlinux.h
	cd $(BPF2GO_OUT) && $(GO) generate ./...

build: generate
	$(GO) build -o bin/$(AGENT) ./cmd/$(AGENT)

run: build
	sudo ./bin/$(AGENT)

clean:
	rm -rf bin/ $(BPF2GO_OUT)/microseg_bpfel.* $(BPF2GO_OUT)/microseg_bpfeb.*

# --- VM workflow (Windows host → NixOS dev VM via SSH on 2222) ---

VM_HOST := root@127.0.0.1
VM_PORT := 2222
VM_DST  := /root/nixos-microsegebpf

vmsync:
	rsync -az --delete -e "ssh -p $(VM_PORT) -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
		--exclude bin/ --exclude .git/ --exclude '*.o' \
		./ $(VM_HOST):$(VM_DST)/

vmbuild: vmsync
	ssh -p $(VM_PORT) -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $(VM_HOST) \
		'cd $(VM_DST) && nix-shell --run "make build"'

vmrun: vmbuild
	ssh -p $(VM_PORT) -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $(VM_HOST) \
		'cd $(VM_DST) && ./bin/$(AGENT) -json'
