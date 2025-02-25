// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/Asphaltt/mybtf"
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

func setLbrConfig(spec *ebpf.CollectionSpec, args []FuncParamFlags, isRetStr bool) error {
	var cfg LbrConfig
	cfg.SetSuppressLbr(suppressLbr)
	cfg.SetOutputStack(outputFuncStack)
	cfg.SetIsRetStr(isRetStr)
	cfg.FilterPid = filterPid
	cfg.FnArgsNr = uint32(len(args))
	for i, arg := range args {
		cfg.FnArgs[i] = arg
	}

	if err := spec.Variables["lbr_config"].Set(cfg); err != nil {
		return fmt.Errorf("failed to set lbr config: %w", err)
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
			if err := fnArg.inject(prog, i, p.Type); err != nil {
				return fmt.Errorf("failed to inject fn arg to bpf prog %s: %w", prog.Name, err)
			}
			return nil
		}
	}

	fnArg.clear(prog)

	return nil
}

func getStructBtfPointer(name string) (*btf.Pointer, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel btf spec: %w", err)
	}

	typ, err := spec.AnyTypeByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get type %s: %w", name, err)
	}

	s, ok := typ.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("type %s is not a struct", name)
	}

	return &btf.Pointer{Target: s}, nil
}

func (t *bpfTracing) injectSkbFilter(prog *ebpf.ProgramSpec, index int, typ btf.Type) error {
	if err := pktFilter.filterSkb(prog, index, typ); err != nil {
		return fmt.Errorf("failed to inject skb pcap-filter: %w", err)
	}

	return nil
}

func (t *bpfTracing) injectXdpFilter(prog *ebpf.ProgramSpec, index int, typ btf.Type) error {
	if err := pktFilter.filterXdp(prog, index, typ); err != nil {
		return fmt.Errorf("failed to inject xdp pcap-filter: %w", err)
	}

	return nil
}

func (t *bpfTracing) injectPktFilter(prog *ebpf.ProgramSpec, params []btf.FuncParam) error {
	for i, p := range params {
		typ := mybtf.UnderlyingType(p.Type)
		ptr, ok := typ.(*btf.Pointer)
		if !ok {
			continue
		}
		stt, ok := ptr.Target.(*btf.Struct)
		if !ok {
			continue
		}

		switch stt.Name {
		case "sk_buff":
			return t.injectSkbFilter(prog, i, typ)

		case "__sk_buff":
			typ, err := getStructBtfPointer("sk_buff")
			if err != nil {
				return err
			}
			return t.injectSkbFilter(prog, i, typ)

		case "xdp_buff":
			return t.injectXdpFilter(prog, i, typ)

		case "xdp_md":
			typ, err := getStructBtfPointer("xdp_buff")
			if err != nil {
				return err
			}
			return t.injectXdpFilter(prog, i, typ)
		}
	}

	pktFilter.clear(prog)

	return nil
}

func (t *bpfTracing) traceProg(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, info bpfTracingInfo) error {
	spec = spec.Copy()

	if err := setLbrConfig(spec, info.params, false); err != nil {
		return fmt.Errorf("failed to set lbr config: %w", err)
	}

	tracingFuncName := TracingProgName(mode)
	progSpec := spec.Programs[tracingFuncName]

	params := info.fn.Type.(*btf.FuncProto).Params
	if err := t.injectFnArg(progSpec, params); err != nil {
		return err
	}
	if err := t.injectPktFilter(progSpec, params); err != nil {
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

	if err := setLbrConfig(spec, fn.Prms, fn.IsRetStr); err != nil {
		return fmt.Errorf("failed to set lbr config: %w", err)
	}

	tracingFuncName := TracingProgName(mode)
	progSpec := spec.Programs[tracingFuncName]

	params := fn.Func.Type.(*btf.FuncProto).Params
	if err := t.injectFnArg(progSpec, params); err != nil {
		return err
	}
	if err := t.injectPktFilter(progSpec, params); err != nil {
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
