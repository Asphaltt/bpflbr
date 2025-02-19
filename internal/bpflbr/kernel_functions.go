// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"fmt"
	"log"
	"os"
	"slices"

	"github.com/cilium/ebpf/btf"
	"github.com/gobwas/glob"
)

const (
	MAX_BPF_FUNC_ARGS = 12
)

func str2glob(funcs []string) ([]glob.Glob, error) {
	globs := make([]glob.Glob, 0, len(funcs))
	for _, fn := range funcs {
		g, err := glob.Compile(fn)
		if err != nil {
			return nil, fmt.Errorf("failed to compile glob from %s: %w", fn, err)
		}

		globs = append(globs, g)
	}
	return globs, nil
}

func isGlobFunc(fn string, globs []glob.Glob) bool {
	for _, g := range globs {
		if g.Match(fn) {
			return true
		}
	}
	return false
}

func FindKernelFuncs(funcs []string) ([]string, error) {
	globs, err := str2glob(funcs)
	if err != nil {
		return nil, err
	}
	kfuncs := make([]string, 0, len(funcs))

	iterBtfSpec := func(spec *btf.Spec) {
		iter := spec.Iterate()
		for iter.Next() {
			if fn, ok := iter.Type.(*btf.Func); ok && isGlobFunc(fn.Name, globs) {
				funcProto := fn.Type.(*btf.FuncProto)
				if len(funcProto.Params) <= MAX_BPF_FUNC_ARGS {
					kfuncs = append(kfuncs, fn.Name)
				} else if verbose {
					log.Printf("Skip function %s with %d args because of limit %d args\n",
						fn.Name, len(funcProto.Params), MAX_BPF_FUNC_ARGS)
				}
			}
		}
	}

	if kfuncAllKmods {
		files, err := os.ReadDir("/sys/kernel/btf")
		if err != nil {
			return nil, fmt.Errorf("failed to read /sys/kernel/btf: %w", err)
		}

		for _, file := range files {
			kmodBtf, err := btf.LoadKernelModuleSpec(file.Name())
			if err != nil {
				return nil, fmt.Errorf("failed to load kernel module BTF: %w", err)
			}

			iterBtfSpec(kmodBtf)
		}
	} else {
		kernelBtf, err := btf.LoadKernelSpec()
		if err != nil {
			return nil, fmt.Errorf("failed to load kernel BTF: %w", err)
		}

		iterBtfSpec(kernelBtf)
	}

	slices.Sort(kfuncs)
	kfuncs = slices.Compact(kfuncs)

	return kfuncs, nil
}
