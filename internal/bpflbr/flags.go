// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	flag "github.com/spf13/pflag"
)

const (
	progFlagDescriptorID     = "id"
	progFlagDescriptorPinned = "pinned"
	progFlagDescriptorTag    = "tag"
	progFlagDescriptorName   = "name"
	progFlagDescriptorPid    = "pid"
)

const (
	TracingModeEntry = "entry"
	TracingModeExit  = "exit"
)

var (
	verbose           bool
	disasmIntelSyntax bool
	mode              string
	filterArg         string
	filterPkt         string

	suppressLbr     bool
	outputFuncStack bool
	filterPid       uint32
	kfuncAllKmods   bool
	noColorOutput   bool
	limitEvents     uint
)

type ProgFlag struct {
	progID uint32
	pinned string
	tag    string
	name   string
	pid    uint32

	descriptor string
	funcName   string

	all bool
}

func parseProgFlag(p string) (ProgFlag, error) {
	var pf ProgFlag

	if p == "*" {
		pf.all = true
		return pf, nil
	}

	id, funcName, ok := strings.Cut(p, ":")
	switch id {
	case "i", "id":
		id, funcName, ok = strings.Cut(funcName, ":")
		break

	case "p", "pinned":
		pf.descriptor = progFlagDescriptorPinned
		pf.pinned, pf.funcName, _ = strings.Cut(funcName, ":")
		if !fileExists(pf.pinned) {
			return pf, fmt.Errorf("pinned file %s does not exist", pf.pinned)
		}
		return pf, nil

	case "t", "tag":
		pf.descriptor = progFlagDescriptorTag
		pf.tag, pf.funcName, _ = strings.Cut(funcName, ":")
		if pf.tag == "" {
			return pf, errors.New("tag must not be empty")
		}
		return pf, nil

	case "n", "name":
		pf.descriptor = progFlagDescriptorName
		pf.name, pf.funcName, _ = strings.Cut(funcName, ":")
		if pf.name == "" {
			return pf, errors.New("name must not be empty")
		}
		return pf, nil

	case "pid":
		pf.descriptor = progFlagDescriptorPid
		id, pf.funcName, _ = strings.Cut(funcName, ":")
		pid, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return pf, fmt.Errorf("failed to parse pid %s from %s: %w", funcName, p, err)
		}
		pf.pid = uint32(pid)
		return pf, nil

	default:
	}

	progID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return pf, fmt.Errorf("failed to parse progID %s from %s: %w", id, p, err)
	}

	pf.descriptor = progFlagDescriptorID
	pf.progID = uint32(progID)
	if ok {
		pf.funcName = funcName
	}

	return pf, nil
}

func parseProgsFlag(progs []string) ([]ProgFlag, error) {
	flags := make([]ProgFlag, 0, len(progs))
	for _, p := range progs {
		pf, err := parseProgFlag(p)
		if err != nil {
			return nil, err
		}

		flags = append(flags, pf)
	}

	return flags, nil
}

type Flags struct {
	progs  []string
	kfuncs []string

	outputFile string

	disasm      bool
	disasmBytes uint
}

func ParseFlags() (*Flags, error) {
	var flags Flags

	f := flag.NewFlagSet("bpflbr", flag.ExitOnError)
	f.StringSliceVarP(&flags.progs, "prog", "p", nil, "bpf prog info for bpflbr in format PROG[,PROG,..], PROG: PROGID[:<prog function name>], PROGID: <prog ID> or 'i/id:<prog ID>' or 'p/pinned:<pinned file>' or 't/tag:<prog tag>' or 'n/name:<prog full name>' or 'pid:<pid>'; all bpf progs will be traced if '*' is specified")
	f.StringSliceVarP(&flags.kfuncs, "kfunc", "k", nil, "filter kernel functions by shell wildcards way")
	f.BoolVar(&kfuncAllKmods, "kfunc-all-kmods", false, "filter functions in all kernel modules")
	f.StringVarP(&flags.outputFile, "output", "o", "", "output file for the result, default is stdout")
	f.BoolVarP(&flags.disasm, "disasm", "d", false, "disasm bpf prog or kernel function")
	f.UintVarP(&flags.disasmBytes, "disasm-bytes", "B", 0, "disasm bytes of kernel function, 0 to guess it automatically")
	f.BoolVar(&disasmIntelSyntax, "disasm-intel-syntax", false, "use Intel asm syntax for disasm, ATT asm syntax by default")
	f.BoolVarP(&verbose, "verbose", "v", false, "output verbose log")
	f.StringVarP(&mode, "mode", "m", TracingModeExit, "mode of lbr tracing, exit or entry")
	f.BoolVar(&suppressLbr, "suppress-lbr", false, "suppress LBR perf event")
	f.BoolVar(&outputFuncStack, "output-stack", false, "output function call stack")
	f.Uint32Var(&filterPid, "filter-pid", 0, "filter pid for tracing")
	f.StringVar(&filterArg, "filter-arg", "", "filter function's argument with simple C expression")
	f.StringVar(&filterPkt, "filter-pkt", "", "filter packet with pcap-filter(7) expr")
	f.UintVar(&limitEvents, "limit-events", 0, "limited number events to output, 0 to output all events")

	err := f.Parse(os.Args)

	noColorOutput = flags.outputFile != "" || !isatty(os.Stdout.Fd())
	fnArg = prepareFuncArgument(filterArg)
	pktFilter = preparePacketFilter(filterPkt)

	return &flags, err
}

func (f *Flags) ParseProgs() ([]ProgFlag, error) {
	return parseProgsFlag(f.progs)
}

func (f *Flags) Kfuncs() []string {
	return f.kfuncs
}

func (f *Flags) OutputFile() string {
	return f.outputFile
}

func (f *Flags) DumpProg() bool {
	return f.disasm
}

func (f *Flags) Disasm() bool {
	return f.disasm
}

func (f *Flags) Mode() string {
	return mode
}

func (f *Flags) SuppressLbr() bool {
	return suppressLbr
}

func (f *Flags) OtherMode() string {
	if mode == TracingModeExit {
		return TracingModeEntry
	}

	return TracingModeExit
}
