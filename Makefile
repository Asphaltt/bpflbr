# Copyright 2024 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

CMD_CD ?= cd
CMD_CP ?= cp
CMD_CHECKSUM ?= sha256sum
CMD_GH ?= gh
CMD_MV ?= mv
CMD_TAR ?= tar

CC ?= gcc

DIR_BIN := ./bin

GOBUILD := go build -v -trimpath
GOBUILD_CGO_CFLAGS := CGO_CFLAGS='-O2 -I$(CURDIR)/lib/capstone/include -I$(CURDIR)/lib/libpcap'
GOBUILD_CGO_LDFLAGS := CGO_LDFLAGS='-g -L$(CURDIR)/lib/capstone/build -L$(CURDIR)/lib/libpcap -lcapstone -lpcap -static'

GOGEN := go generate

BPF_OBJ := lbr_bpfel.o lbr_bpfeb.o feat_bpfel.o feat_bpfeb.o
BPF_SRC := bpf/lbr.c bpf/feature.c

BPFLBR_OBJ := bpflbr
BPFLBR_CSM := $(BPFLBR_OBJ).sha256sum
RELEASE_NOTES ?= release_notes.txt

LIBPCAP_OBJ := lib/libpcap/libpcap.a

LIBCAPSTONE_OBJ := lib/capstone/build/libcapstone.a

.DEFAULT_GOAL := $(BPFLBR_OBJ)

# Build libpcap for static linking
$(LIBPCAP_OBJ):
	cd lib/libpcap && \
		./autogen.sh && \
		./configure --disable-rdma --disable-shared --disable-usb --disable-netmap --disable-bluetooth --disable-dbus --without-libnl --host=$(LIBPCAP_ARCH) && \
		make

# Build libcapstone for static linking
$(LIBCAPSTONE_OBJ):
	cd lib/capstone && \
		cmake -B build -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_ARCHITECTURE_DEFAULT=1 -DCAPSTONE_BUILD_CSTOOL=0 && \
		cmake --build build

$(BPF_OBJ): $(BPF_SRC)
	$(GOGEN)

$(BPFLBR_OBJ): $(BPF_OBJ) $(LIBPCAP_OBJ) $(LIBCAPSTONE_OBJ)
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
