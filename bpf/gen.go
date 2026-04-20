// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT
//
// Code generation directive: bpf2go compiles the C source in this directory
// and emits Go bindings (struct definitions, map accessors, program loaders)
// next to it. We pin BTF-based CO-RE to keep the binary kernel-agnostic.

package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip -target bpfel -type lpm_v4_key -type lpm_v6_key -type policy_value -type flow_event -type default_cfg Microseg microseg.c -- -I. -I./headers -O2 -g -Wall
