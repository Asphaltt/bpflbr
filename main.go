// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/knightsc/gapstone"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/Asphaltt/bpflbr/internal/assert"
	"github.com/Asphaltt/bpflbr/internal/bpflbr"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang lbr ./bpf/lbr.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -I./lib/libbpf/src -I./lib/libbpf/include -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang feat ./bpf/feature.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -I./lib/libbpf/src -I./lib/libbpf/include -Wall

func main() {
	flags, err := bpflbr.ParseFlags()
	assert.NoErr(err, "Failed to parse flags: %v")

	if flags.Disasm() {
		bpflbr.Disasm(flags)
		return
	}

	mode := flags.Mode()
	assert.True(slices.Contains([]string{bpflbr.TracingModeEntry, bpflbr.TracingModeExit}, mode),
		fmt.Sprintf("Mode (%s) must be exit or entry", mode))

	progs, err := flags.ParseProgs()
	assert.NoErr(err, "Failed to parse bpf prog infos: %v")

	featBPFSpec, err := loadFeat()
	assert.NoErr(err, "Failed to load feat bpf spec: %v")

	err = bpflbr.DetectBPFFeatures(featBPFSpec)
	assert.NoErr(err, "Failed to detect bpf features: %v")

	if !flags.SuppressLbr() {
		lbrPerfEvents, err := bpflbr.OpenLbrPerfEvent()
		if err != nil &&
			(errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP)) {
			log.Fatalln("LBR is not supported on current system")
		}
		assert.NoErr(err, "Failed to open LBR perf event: %v")
		defer lbrPerfEvents.Close()
	}

	bpflbr.VerboseLog("Reading /proc/kallsyms ..")
	kallsyms, err := bpflbr.NewKallsyms()
	assert.NoErr(err, "Failed to read /proc/kallsyms: %v")

	var addr2line *bpflbr.Addr2Line

	vmlinux, err := bpflbr.FindVmlinux()
	if err != nil {
		if errors.Is(err, bpflbr.ErrNotFound) {
			bpflbr.VerboseLog("Dbgsym vmlinux not found")
		} else {
			assert.NoErr(err, "Failed to find vmlinux: %v")
		}
	}
	if err == nil {
		bpflbr.VerboseLog("Found vmlinux: %s", vmlinux)

		textAddr, err := bpflbr.ReadTextAddrFromVmlinux(vmlinux)
		assert.NoErr(err, "Failed to read .text address from vmlinux: %v")

		bpflbr.VerboseLog("Creating addr2line from vmlinux ..")
		kaslr := bpflbr.NewKaslr(kallsyms.Stext(), textAddr)
		addr2line, err = bpflbr.NewAddr2Line(vmlinux, kaslr, kallsyms.SysBPF())
		assert.NoErr(err, "Failed to create addr2line: %v")
	}

	engine, err := gapstone.New(int(gapstone.CS_ARCH_X86), int(gapstone.CS_MODE_64))
	assert.NoErr(err, "Failed to create capstone engine: %v")
	defer engine.Close()

	bpflbr.VerboseLog("Disassembling bpf progs ..")
	bpfProgs, err := bpflbr.NewBPFProgs(progs, false, false)
	assert.NoErr(err, "Failed to get bpf progs: %v")
	defer bpfProgs.Close()

	kfuncs, err := bpflbr.FindKernelFuncs(flags.Kfuncs(), kallsyms)
	assert.NoErr(err, "Failed to find kernel functions: %v")

	tracingTargets := bpfProgs.Tracings()
	assert.True(len(tracingTargets)+len(kfuncs) != 0, "No tracing target")

	bpflbr.VerboseLog("Tracing bpf progs or kernel functions ..")
	bpfSpec, err := loadLbr()
	assert.NoErr(err, "Failed to load bpf spec: %v")
	delete(bpfSpec.Programs, bpflbr.TracingProgName(flags.OtherMode()))

	numCPU, err := ebpf.PossibleCPU()
	assert.NoErr(err, "Failed to get possible cpu: %v")

	lbrsMapSpec := bpfSpec.Maps[".data.lbrs"]
	lbrsMapSpec.Flags |= unix.BPF_F_MMAPABLE
	lbrsMapSpec.ValueSize = uint32(unsafe.Sizeof(bpflbr.Event{})) * uint32(numCPU)
	lbrsMapSpec.Contents[0].Value = make([]byte, lbrsMapSpec.ValueSize)
	lbrs, err := ebpf.NewMap(lbrsMapSpec)
	assert.NoErr(err, "Failed to create lbrs map: %v")

	funcStacks, err := ebpf.NewMap(bpfSpec.Maps["func_stacks"])
	assert.NoErr(err, "Failed to create func_stacks map: %v")
	defer funcStacks.Close()

	readyDataMapSpec := bpfSpec.Maps[".data.ready"]
	readyDataMapSpec.Flags |= unix.BPF_F_MMAPABLE
	readyDataMap, err := ebpf.NewMap(readyDataMapSpec)
	assert.NoErr(err, "Failed to create ready data map: %v")
	defer readyDataMap.Close()

	events, err := ebpf.NewMap(bpfSpec.Maps["events"])
	assert.NoErr(err, "Failed to create events map: %v")
	defer events.Close()

	reusedMaps := map[string]*ebpf.Map{
		"events":      events,
		".data.lbrs":  lbrs,
		".data.ready": readyDataMap,
		"func_stacks": funcStacks,
	}

	if len(kfuncs) != 0 && len(progs) == 0 {
		tracingTargets = tracingTargets[:0]
	}

	if len(kfuncs) > 20 {
		log.Printf("bpflbr is tracing %d kernel functions, this may take a while", len(kfuncs))
	}

	tracings, err := bpflbr.NewBPFTracing(bpfSpec, reusedMaps, tracingTargets, kfuncs)
	assert.NoVerifierErr(err, "Failed to trace: %v")
	defer tracings.Close()
	assert.True(tracings.HaveTracing(), "No tracing target")

	err = bpfProgs.AddProgs(tracings.Progs(), true)
	assert.NoErr(err, "Failed to add bpf progs: %v")

	kallsyms, err = bpflbr.NewKallsyms()
	assert.NoErr(err, "Failed to reread /proc/kallsyms: %v")

	reader, err := ringbuf.NewReader(events)
	assert.NoErr(err, "Failed to create ringbuf reader: %v")
	defer reader.Close()

	w := os.Stdout
	if flags.OutputFile() != "" {
		f, err := os.OpenFile(flags.OutputFile(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		assert.NoErr(err, "Failed to create output file: %v")
		defer f.Close()
		w = f
	}

	err = readyDataMap.Put(uint32(0), uint32(1))
	assert.NoErr(err, "Failed to update ready data map: %v")
	defer readyDataMap.Put(uint32(0), uint32(0))

	log.Print("bpflbr is running..")
	defer log.Print("bpflbr is exiting..")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		<-ctx.Done()
		_ = reader.Close()
		return nil
	})

	errg.Go(func() error {
		return bpflbr.Run(reader, bpfProgs, addr2line, kallsyms, kfuncs, funcStacks, w)
	})

	err = errg.Wait()
	if err == bpflbr.ErrFinished {
		return
	}
	assert.NoErr(err, "Failed: %v")
}
