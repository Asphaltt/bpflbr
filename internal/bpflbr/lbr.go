// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

func Run(reader *ringbuf.Reader, progs *bpfProgs, addr2line *Addr2Line, ksyms *Kallsyms, w io.Writer) error {
	type LbrEntry struct {
		From  uintptr
		To    uintptr
		Flags uint64
	}
	type Event struct {
		Entries [32]LbrEntry
		NrBytes int64
		Retval  int64
		FuncIP  uintptr
	}

	stack := newLBRStack()

	var sb strings.Builder

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}

			return fmt.Errorf("failed to read ringbuf: %w", err)
		}

		if len(record.RawSample) < int(unsafe.Sizeof(Event{})) {
			continue
		}

		event := (*Event)(unsafe.Pointer(&record.RawSample[0]))

		if event.NrBytes < 0 && event.NrBytes == -int64(unix.ENOENT) {
			return fmt.Errorf("LBR not supported")
		}

		hasEntries := event.NrBytes > 0 && event.Entries[0] != (LbrEntry{})
		if !hasEntries {
			continue
		}

		nrEntries := event.NrBytes / int64(8*3)
		lbrEntries := make([]branchEntry, 0, nrEntries)
		for i := 0; i < int(nrEntries); i++ {
			entry := event.Entries[i]
			if entry == (LbrEntry{}) {
				break
			}

			from := getLineInfo(entry.From, progs, addr2line, ksyms)
			to := getLineInfo(entry.To, progs, addr2line, ksyms)
			lbrEntries = append(lbrEntries, branchEntry{from, to})
		}

		if len(lbrEntries) == 0 {
			continue
		}

		last := len(lbrEntries) - 1
		stack.pushFirstEntry(lbrEntries[last])
		for i := last - 1; i >= 0; i-- {
			stack.pushEntry(lbrEntries[i])
		}

		progName := progs.ksyms[event.FuncIP]
		if progName == "" {
			progName = fmt.Sprintf("UNKNOWN@%#x", event.FuncIP)
		}

		fmt.Fprintf(&sb, "Recv a record for %s with retval=%d :\n", progName, event.Retval)
		stack.output(&sb)
		fmt.Fprintln(w, sb.String())

		sb.Reset()
		stack.reset()
	}
}

func getLineInfo(addr uintptr, progs *bpfProgs, a2l *Addr2Line, ksyms *Kallsyms) *branchEndpoint {
	if li, ok := progs.get(addr); ok {
		var ep branchEndpoint
		ep.addr = addr
		ep.offset = addr - li.ksymAddr
		ep.funcName = li.funcName
		ep.fileName = li.fileName
		ep.fileLine = li.fileLine
		ep.updateInfo()
		return &ep
	}

	var ep branchEndpoint
	ep.addr = addr
	defer ep.updateInfo()

	if ksym, ok := ksyms.find(addr); ok {
		ep.funcName = ksym.name
		ep.offset = addr - uintptr(ksym.addr)
	}

	li, err := a2l.get(addr)
	if err != nil {
		return &ep
	}

	fileName := li.File
	if strings.HasPrefix(fileName, a2l.buildDir) {
		fileName = fileName[len(a2l.buildDir):]
	}

	ep.funcName = li.Func
	ep.fileName = fileName
	ep.fileLine = uint32(li.Line)
	return &ep
}