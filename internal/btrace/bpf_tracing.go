// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type bpfTracing struct {
	llock sync.Mutex
	progs []*ebpf.Program
	links []link.Link
	klnks []link.Link
}

func (t *bpfTracing) Progs() []*ebpf.Program {
	return t.progs
}

func setBtraceConfig(spec *ebpf.CollectionSpec, args []FuncParamFlags, isRetStr bool) error {
	var cfg BtraceConfig
	cfg.SetOutputLbr(outputLbr)
	cfg.SetOutputStack(outputFuncStack)
	cfg.SetIsRetStr(isRetStr)
	cfg.FilterPid = filterPid
	cfg.FnArgsNr = uint32(len(args))
	for i, arg := range args {
		cfg.FnArgs[i] = arg
	}

	if err := spec.Variables["btrace_config"].Set(cfg); err != nil {
		return fmt.Errorf("failed to set btrace config: %w", err)
	}

	return nil
}

func NewBPFTracing(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, infos []bpfTracingInfo, kfuncs KFuncs) (*bpfTracing, error) {
	var t bpfTracing
	t.links = make([]link.Link, 0, len(infos))

	var errg errgroup.Group

	for _, info := range infos {
		info := info
		errg.Go(func() error {
			return t.traceProg(spec, reusedMaps, info)
		})
	}

	for _, fn := range kfuncs {
		fn := fn
		errg.Go(func() error {
			return t.traceFunc(spec, reusedMaps, fn)
		})
	}

	if err := errg.Wait(); err != nil {
		t.Close()
		return nil, fmt.Errorf("failed to trace bpf progs: %w", err)
	}

	return &t, nil
}

func (t *bpfTracing) HaveTracing() bool {
	t.llock.Lock()
	defer t.llock.Unlock()

	return len(t.links) > 0 || len(t.klnks) > 0
}

func (t *bpfTracing) Close() {
	t.llock.Lock()
	defer t.llock.Unlock()

	var errg errgroup.Group

	for _, l := range t.links {
		l := l
		errg.Go(func() error {
			return l.Close()
		})
	}

	errg.Go(func() error {
		for _, l := range t.klnks {
			_ = l.Close()
		}
		return nil
	})

	_ = errg.Wait()
}

func TracingProgName(mode string) string {
	return fmt.Sprintf("f%s_fn", mode)
}

func (t *bpfTracing) injectFnArg(prog *ebpf.ProgramSpec, params []btf.FuncParam) error {
	for i, p := range params {
		if p.Name == fnArg.name {
			err := fnArg.inject(prog, i, p.Type)
			if err != nil {
				return fmt.Errorf("failed to inject func arg filter expr: %w", err)
			}

			return nil
		}
	}

	fnArg.clear(prog)

	return nil
}

func (t *bpfTracing) traceProg(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, info bpfTracingInfo) error {
	spec = spec.Copy()

	if err := setBtraceConfig(spec, info.params, false); err != nil {
		return fmt.Errorf("failed to set btrace config: %w", err)
	}

	tracingFuncName := TracingProgName(mode)
	progSpec := spec.Programs[tracingFuncName]
	params := info.fn.Type.(*btf.FuncProto).Params
	if err := t.injectFnArg(progSpec, params); err != nil {
		return err
	}

	attachType := ebpf.AttachTraceFExit
	if mode == TracingModeEntry {
		attachType = ebpf.AttachTraceFEntry
	}

	progSpec.AttachTarget = info.prog
	progSpec.AttachTo = info.funcName
	progSpec.AttachType = attachType

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		return fmt.Errorf("failed to create bpf collection for tracing: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingFuncName]
	delete(coll.Programs, tracingFuncName)

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: attachType,
	})
	if err != nil {
		_ = prog.Close()
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	if verbose {
		log.Printf("Tracing %s of prog %v", info.funcName, info.prog)
	}

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.links = append(t.links, l)
	t.llock.Unlock()

	return nil
}

func (t *bpfTracing) traceFunc(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, fn KFunc) error {
	spec = spec.Copy()

	if err := setBtraceConfig(spec, fn.Prms, fn.IsRetStr); err != nil {
		return fmt.Errorf("failed to set btrace config: %w", err)
	}

	tracingFuncName := TracingProgName(mode)
	progSpec := spec.Programs[tracingFuncName]
	params := fn.Func.Type.(*btf.FuncProto).Params
	if err := t.injectFnArg(progSpec, params); err != nil {
		return err
	}

	attachType := ebpf.AttachTraceFExit
	if mode == TracingModeEntry {
		attachType = ebpf.AttachTraceFEntry
	}

	fnName := fn.Func.Name
	progSpec.AttachTo = fnName
	progSpec.AttachType = attachType

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("failed to create bpf collection for tracing: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingFuncName]
	delete(coll.Programs, tracingFuncName)
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: attachType,
	})
	if err != nil {
		_ = prog.Close()
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) {
			return nil
		}
		if errors.Is(err, unix.EBUSY) /* Because no nop5 at the function entry, especially non-traceable funcs */ {
			if verbose {
				log.Printf("Cannot trace kernel function %s", fnName)
			}
			return nil
		}
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	if verbose {
		log.Printf("Tracing kernel function %s", fnName)
	}

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.klnks = append(t.klnks, l)
	t.llock.Unlock()

	return nil
}
