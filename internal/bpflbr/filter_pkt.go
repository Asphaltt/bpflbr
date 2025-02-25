// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/jschwinger233/elibpcap"
)

const (
	pcapFilterL2Stub = "filter_pcap_l2"
	pcapFilterL3Stub = "filter_pcap_l3"

	filterSkbFunc = "filter_skb"
	filterXdpFunc = "filter_xdp"
	filterPktFunc = "filter_pkt"
)

var pktFilter packetFilter

type packetFilter struct {
	expr string
}

func preparePacketFilter(expr string) packetFilter {
	var pf packetFilter
	pf.expr = expr
	return pf
}

func (pf *packetFilter) injectSkbInsns(prog *ebpf.ProgramSpec) error {
	insns, err := elibpcap.Inject(pf.expr, prog.Instructions, elibpcap.Options{
		AtBpf2Bpf:  pcapFilterL2Stub,
		DirectRead: false,
		L2Skb:      true,
	})
	if err != nil {
		return fmt.Errorf("failed to inject l2 pcap-filter: %w", err)
	}

	prog.Instructions = insns

	insns, err = elibpcap.CompileEbpf(pf.expr, elibpcap.Options{
		AtBpf2Bpf:  pcapFilterL3Stub,
		DirectRead: false,
		L2Skb:      false,
	})
	if err != nil {
		// Reject all packets when there's l2 pcap-filter expr, e.g. vlan, for
		// l3 stub.
		insns = asm.Instructions{
			asm.Mov.Reg(asm.R4, asm.R5), // r4 = r5 (data = data_end)
		}
	}

	startIdx, ok := findStartIndex(prog, pcapFilterL3Stub)
	if !ok {
		return fmt.Errorf("cannot find %s", pcapFilterL3Stub)
	}

	insns[0] = insns[0].WithMetadata(prog.Instructions[startIdx].Metadata)
	prog.Instructions[startIdx] = prog.Instructions[startIdx].WithMetadata(asm.Metadata{})
	prog.Instructions = append(prog.Instructions[:startIdx],
		append(insns, prog.Instructions[startIdx:]...)...)

	return nil
}

func (pf *packetFilter) injectXdpInsns(prog *ebpf.ProgramSpec) error {
	insns, err := elibpcap.Inject(pf.expr, prog.Instructions, elibpcap.Options{
		AtBpf2Bpf:  pcapFilterL2Stub,
		DirectRead: false,
		L2Skb:      true,
	})
	if err != nil {
		return fmt.Errorf("failed to inject l2 pcap-filter: %w", err)
	}

	prog.Instructions = insns

	return nil
}

func (pf *packetFilter) genFilterInsns(index int, stub string) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, -8),
		asm.Mov.Imm(asm.R2, int32(index)),
		asm.FnGetFuncArg.Call(),
		asm.LoadMem(asm.R1, asm.R10, -8, asm.DWord),
		asm.Call.Label(stub),
		asm.Return(),
	}
}

func (pf *packetFilter) filterSkb(prog *ebpf.ProgramSpec, index int) error {
	// clear filter_xdp stub
	clearSubprog(prog, filterXdpFunc)

	// update filter_pkt stub
	injectInsns(prog, filterPktFunc, pf.genFilterInsns(index, filterSkbFunc))

	return pf.injectSkbInsns(prog)
}

func (pf *packetFilter) filterXdp(prog *ebpf.ProgramSpec, index int) error {
	// clear filter_skb stub
	clearSubprog(prog, filterSkbFunc)
	// clar filter_pcap_l3 stub
	clearSubprog(prog, pcapFilterL3Stub)

	// update filter_pkt stub
	injectInsns(prog, filterPktFunc, pf.genFilterInsns(index, filterXdpFunc))

	return pf.injectXdpInsns(prog)
}
