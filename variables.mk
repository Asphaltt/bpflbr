# Copyright 2025 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

CMD_CD ?= cd
CMD_CP ?= cp
CMD_CHECKSUM ?= sha256sum
CMD_GH ?= gh
CMD_MV ?= mv
CMD_TAR ?= tar
CMD_BPFTOOL ?= bpftool

CC ?= gcc

DIR_BIN := ./bin

GOBUILD := go build -v -trimpath
GOBUILD_CGO_CFLAGS := CGO_CFLAGS='-O2 -I$(CURDIR)/lib/capstone/include -I$(CURDIR)/lib/libpcap'
GOBUILD_CGO_LDFLAGS := CGO_LDFLAGS='-g -L$(CURDIR)/lib/capstone/build -L$(CURDIR)/lib/libpcap -lcapstone -lpcap -static'

GOGEN := go generate

VMLINUX_OBJ := bpf/headers/vmlinux.h

BPF_OBJ := lbr_bpfel.o lbr_bpfeb.o feat_bpfel.o feat_bpfeb.o
BPF_SRC := bpf/lbr.c bpf/feature.c

BPFLBR_OBJ := bpflbr
BPFLBR_CSM := $(BPFLBR_OBJ).sha256sum
RELEASE_NOTES ?= release_notes.txt

LIBPCAP_OBJ := lib/libpcap/libpcap.a

LIBCAPSTONE_OBJ := lib/capstone/build/libcapstone.a
