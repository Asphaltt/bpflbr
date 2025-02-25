# Copyright 2024 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

CMD_CD ?= cd
CMD_CP ?= cp
CMD_CHECKSUM ?= sha256sum
CMD_GH ?= gh
CMD_MV ?= mv
CMD_TAR ?= tar

CMD_CC ?= clang
CMD_CXX ?= clang++

DIR_BIN := ./bin

GOBUILD := go build -v -trimpath
GOBUILD_CGO_CFLAGS := CGO_CFLAGS='-O2 -I$(CURDIR)/lib/libpcap'
GOBUILD_CGO_LDFLAGS := CGO_LDFLAGS='-O2 -g -L$(CURDIR)/lib/libpcap -lcapstone -lpcap -static'

GOGEN := go generate

BPF_OBJ := lbr_bpfel.o lbr_bpfeb.o feat_bpfel.o feat_bpfeb.o
BPF_SRC := bpf/lbr.c bpf/feature.c

BPFLBR_OBJ := bpflbr
BPFLBR_SRC := $(shell find internal -type f -name '*.go') main.go
BPFLBR_CSM := $(BPFLBR_OBJ).sha256sum
RELEASE_NOTES ?= release_notes.txt

LIBPCAP_OBJ := lib/libpcap/libpcap.a

.DEFAULT_GOAL := $(BPFLBR_OBJ)

# Build libpcap for static linking
$(LIBPCAP_OBJ):
	cd lib/libpcap && \
		./autogen.sh && \
		CC=$(CMD_CC) CXX=$(CMD_CXX) ./configure --disable-rdma --disable-shared --disable-usb --disable-netmap --disable-bluetooth --disable-dbus --without-libnl && \
		make

$(BPF_OBJ): $(BPF_SRC)
	$(GOGEN)

$(BPFLBR_OBJ): $(BPF_OBJ) $(BPFLBR_SRC) $(LIBPCAP_OBJ)
	$(GOBUILD_CGO_CFLAGS) $(GOBUILD_CGO_LDFLAGS) $(GOBUILD)

.PHONY: local_release
local_release: $(BPFLBR_OBJ)
	@$(CMD_CP) $(BPFLBR_OBJ) $(DIR_BIN)/$(BPFLBR_OBJ)
	$(CMD_CHECKSUM) $(BPFLBR_OBJ) > $(DIR_BIN)/$(BPFLBR_CSM)

.PHONY: clean
clean:
	rm -f $(BPF_OBJ)
	rm -f bpflbr
	rm -rf $(DIR_BIN)/*
	@touch $(DIR_BIN)/.gitkeep

.PHONY: publish
publish: local_release
	@if [ -z "$(VERSION)" ]; then echo "VERSION is not set"; exit 1; fi
	$(CMD_TAR) -czf $(DIR_BIN)/$(BPFLBR_OBJ)-$(VERSION)-linux-amd64.tar.gz $(DIR_BIN)/$(BPFLBR_OBJ) $(DIR_BIN)/$(BPFLBR_CSM)
	@$(CMD_MV) $(RELEASE_NOTES) $(DIR_BIN)/$(RELEASE_NOTES)
	$(CMD_GH) release create $(VERSION) $(DIR_BIN)/$(BPFLBR_OBJ)-$(VERSION)-linux-amd64.tar.gz --title "bpflbr $(VERSION)" --notes-file $(DIR_BIN)/$(RELEASE_NOTES)
