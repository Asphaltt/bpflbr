// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"os"

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

	outputLbr       bool
	outputFuncStack bool
	filterPid       uint32
	kfuncAllKmods   bool
	noColorOutput   bool
	limitEvents     uint
)

type Flags struct {
	progs  []string
	kfuncs []string

	outputFile string

	disasm      bool
	disasmBytes uint
}

func ParseFlags() (*Flags, error) {
	var flags Flags

	f := flag.NewFlagSet("btrace", flag.ExitOnError)
	f.StringSliceVarP(&flags.progs, "prog", "p", nil, "bpf prog info for btrace in format PROG[,PROG,..], PROG: PROGID[:<prog function name>], PROGID: <prog ID> or 'i/id:<prog ID>' or 'p/pinned:<pinned file>' or 't/tag:<prog tag>' or 'n/name:<prog full name>' or 'pid:<pid>'; all bpf progs will be traced if '*' is specified")
	f.StringSliceVarP(&flags.kfuncs, "kfunc", "k", nil, "filter kernel functions by shell wildcards way")
	f.BoolVar(&kfuncAllKmods, "kfunc-all-kmods", false, "filter functions in all kernel modules")
	f.StringVarP(&flags.outputFile, "output", "o", "", "output file for the result, default is stdout")
	f.BoolVarP(&flags.disasm, "disasm", "d", false, "disasm bpf prog or kernel function")
	f.UintVarP(&flags.disasmBytes, "disasm-bytes", "B", 0, "disasm bytes of kernel function, 0 to guess it automatically")
	f.BoolVar(&disasmIntelSyntax, "disasm-intel-syntax", false, "use Intel asm syntax for disasm, ATT asm syntax by default")
	f.BoolVarP(&verbose, "verbose", "v", false, "output verbose log")
	f.StringVarP(&mode, "mode", "m", TracingModeExit, "mode of btrace, exit or entry")
	f.BoolVar(&outputLbr, "output-lbr", false, "output LBR perf event")
	f.BoolVar(&outputFuncStack, "output-stack", false, "output function call stack")
	f.Uint32Var(&filterPid, "filter-pid", 0, "filter pid for tracing")
	f.StringVar(&filterArg, "filter-arg", "", "filter function's argument with C expression, e.g. 'prog->type == BPF_PROG_TYPE_TRACING'")
	f.UintVar(&limitEvents, "limit-events", 0, "limited number events to output, 0 to output all events")

	err := f.Parse(os.Args)

	noColorOutput = flags.outputFile != "" || !isatty(os.Stdout.Fd())
	fnArg = prepareFuncArgument(filterArg)

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

func (f *Flags) OutputLbr() bool {
	return outputLbr
}

func (f *Flags) OtherMode() string {
	if mode == TracingModeExit {
		return TracingModeEntry
	}

	return TracingModeExit
}
