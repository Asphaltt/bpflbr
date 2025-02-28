// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/leonhwangprojects/bice"
	"github.com/leonhwangprojects/btrace/internal/strx"
)

const (
	injectStubFilterArg = "filter_fnarg"
)

var fnArg funcArgument

type funcArgument struct {
	expr string
	name string
}

func prepareFuncArgument(expr string) funcArgument {
	var arg funcArgument
	arg.expr = expr

	for i := 0; i < len(expr); i++ {
		if !strx.IsChar(expr[i]) {
			arg.name = expr[:i]
			break
		}
	}

	return arg
}

func (arg *funcArgument) compile(idx int, t btf.Type) (asm.Instructions, error) {
	insns, err := bice.SimpleCompile(arg.expr, t)
	if err != nil {
		return nil, fmt.Errorf("failed to compile expression %s: %v", arg.expr, err)
	}

	return append(asm.Instructions{
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, -8),
		asm.Mov.Imm(asm.R2, int32(idx)),
		// r1 is ctx already
		asm.FnGetFuncArg.Call(),
		asm.LoadMem(asm.R1, asm.R10, -8, asm.DWord),
	}, insns...), nil
}

func (arg *funcArgument) clear(prog *ebpf.ProgramSpec) {
	clearSubprog(prog, injectStubFilterArg)
}

func (arg *funcArgument) inject(prog *ebpf.ProgramSpec, idx int, t btf.Type) error {
	if arg.expr == "" {
		arg.clear(prog)
		return nil
	}

	insns, err := arg.compile(idx, t)
	if err != nil {
		return err
	}

	injectInsns(prog, injectStubFilterArg, insns)

	return nil
}
