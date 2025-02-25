// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/jschwinger233/elibpcap"
	"github.com/leonhwangprojects/bice"
)

const (
	pcapFilterL2Stub = "filter_pcap_l2"
	pcapFilterL3Stub = "filter_pcap_l3"

	pcapFilterL2StubSpecialized = "filter_pcap_l2.specialized.1"
	pcapFilterL3StubSpecialized = "filter_pcap_l3.specialized.1"

	filterSkbFunc = "filter_skb"
	filterXdpFunc = "filter_xdp"
	filterPktFunc = "filter_pkt"

	labelExitFilterPkt   = "__exit_filter_pkt"
	labelReturnFilterPkt = "__return_filter_pkt"
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

func (pf *packetFilter) genGetFuncArg(index int, dst asm.Register) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, -8),
		asm.Mov.Imm(asm.R2, int32(index)),
		asm.FnGetFuncArg.Call(),
		asm.LoadMem(dst, asm.R10, -8, asm.DWord),
	}
}

func (pf *packetFilter) filterSkb(prog *ebpf.ProgramSpec, index int, t btf.Type) error {
	if pf.expr == "" {
		pf.clear(prog)
		return nil
	}

	var err error
	prog.Instructions, err = elibpcap.Inject(pf.expr, prog.Instructions, elibpcap.Options{
		AtBpf2Bpf:  pcapFilterL2Stub,
		DirectRead: false,
		L2Skb:      true,
	})
	if err != nil {
		return fmt.Errorf("failed to inject l2 pcap-filter: %w", err)
	}
	prog.Instructions, err = elibpcap.Inject(pf.expr, prog.Instructions, elibpcap.Options{
		AtBpf2Bpf:  pcapFilterL3Stub,
		DirectRead: false,
		L2Skb:      false,
	})
	if err != nil {
		VerboseLog("Failed to inject l3 pcap-filter: %v", err)
		prog.Instructions, _ = elibpcap.Inject("__reject_all__", prog.Instructions, elibpcap.Options{
			AtBpf2Bpf:  pcapFilterL3Stub,
			DirectRead: false,
			L2Skb:      false,
		})
	}

	pf.clearSpecializedStubs(prog)
	clearSubprog(prog, filterSkbFunc)
	clearSubprog(prog, filterXdpFunc)

	insns := pf.genGetFuncArg(index, asm.R6) // R6 = skb
	insns, _, err = bice.Access(bice.AccessOptions{
		Insns:     insns,
		Expr:      "skb->mac_len", // R7 = skb->mac_len
		Type:      t,
		Src:       asm.R6,
		Dst:       asm.R7,
		LabelExit: labelExitFilterPkt,
	})
	if err != nil {
		return fmt.Errorf("failed to access skb->mac_len: %w", err)
	}

	insns, _, err = bice.Access(bice.AccessOptions{
		Insns:     insns,
		Expr:      "skb->mac_header", // R8 = skb->mac_header
		Type:      t,
		Src:       asm.R6,
		Dst:       asm.R8,
		LabelExit: labelExitFilterPkt,
	})
	if err != nil {
		return fmt.Errorf("failed to access skb->mac_header: %w", err)
	}

	insns, _, err = bice.Access(bice.AccessOptions{
		Insns:     insns,
		Expr:      "skb->network_header", // R9 = skb->network_header
		Type:      t,
		Src:       asm.R6,
		Dst:       asm.R9,
		LabelExit: labelExitFilterPkt,
	})
	if err != nil {
		return fmt.Errorf("failed to access skb->network_header: %w", err)
	}

	insns, _, err = bice.Access(bice.AccessOptions{
		Insns:     insns,
		Expr:      "skb->head", // R4 = skb->head
		Type:      t,
		Src:       asm.R6,
		Dst:       asm.R4,
		LabelExit: labelExitFilterPkt,
	})
	if err != nil {
		return fmt.Errorf("failed to access skb->head: %w", err)
	}
	insns = append(insns,
		asm.StoreMem(asm.R10, -16, asm.R4, asm.DWord),
	)

	insns, _, err = bice.Access(bice.AccessOptions{
		Insns:     insns,
		Expr:      "skb->tail", // R5 = skb->tail
		Type:      t,
		Src:       asm.R6,
		Dst:       asm.R5,
		LabelExit: labelExitFilterPkt,
	})
	if err != nil {
		return fmt.Errorf("failed to access skb->tail: %w", err)
	}

	const labelCallPcapFilterL3 = "__call_pcap_filter_l3"

	insns = append(insns,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Reg(asm.R2, asm.R6),
		asm.Mov.Reg(asm.R3, asm.R6),
		asm.LoadMem(asm.R4, asm.R10, -16, asm.DWord),
		// R5 = skb->head + skb->tail
		asm.Add.Reg(asm.R5, asm.R4),

		// return skb->mac_len ? pcap_filter_l2() : pcap_filter_l3();
		asm.JEq.Imm(asm.R7, 0, labelCallPcapFilterL3),
		// R4 = skb->head + skb->mac_header
		asm.Add.Reg(asm.R4, asm.R8),
		asm.Call.Label(pcapFilterL2Stub),
		asm.Ja.Label(labelReturnFilterPkt),
		// R4 = skb->head + skb->network_header
		asm.Add.Reg(asm.R4, asm.R9).WithSymbol(labelCallPcapFilterL3),
		asm.Call.Label(pcapFilterL3Stub),
		asm.Ja.Label(labelReturnFilterPkt),
		asm.Return().WithSymbol(labelReturnFilterPkt),
	)

	// update filter_pkt stub
	injectInsns(prog, filterPktFunc, insns)

	return nil
}

func (pf *packetFilter) filterXdp(prog *ebpf.ProgramSpec, index int, t btf.Type) error {
	if pf.expr == "" {
		pf.clear(prog)
		return nil
	}

	var err error
	prog.Instructions, err = elibpcap.Inject(pf.expr, prog.Instructions, elibpcap.Options{
		AtBpf2Bpf:  pcapFilterL2Stub,
		DirectRead: false,
		L2Skb:      true,
	})
	if err != nil {
		return fmt.Errorf("failed to inject l2 pcap-filter: %w", err)
	}

	pf.clearSpecializedStubs(prog)
	clearSubprog(prog, filterSkbFunc)
	clearSubprog(prog, filterXdpFunc)
	clearSubprog(prog, pcapFilterL3Stub)

	insns := pf.genGetFuncArg(index, asm.R6) // R6 = xdp
	insns, _, err = bice.Access(bice.AccessOptions{
		Insns:     insns,
		Expr:      "xdp->data", // R7 = xdp->data
		Type:      t,
		Src:       asm.R6,
		Dst:       asm.R7,
		LabelExit: labelExitFilterPkt,
	})
	if err != nil {
		return fmt.Errorf("failed to access xdp->data: %w", err)
	}

	insns, _, err = bice.Access(bice.AccessOptions{
		Insns:     insns,
		Expr:      "xdp->data_end", // R5 = xdp->data_end
		Type:      t,
		Src:       asm.R6,
		Dst:       asm.R5,
		LabelExit: labelExitFilterPkt,
	})
	if err != nil {
		return fmt.Errorf("failed to access xdp->data: %w", err)
	}

	insns = append(insns,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Reg(asm.R2, asm.R6),
		asm.Mov.Reg(asm.R3, asm.R6),
		// R4 = xdp->data
		asm.Mov.Reg(asm.R4, asm.R7),
		// R5 = xdp->data_end
		asm.Call.Label(pcapFilterL2Stub),
		asm.Ja.Label(labelReturnFilterPkt),
		asm.Return().WithSymbol(labelReturnFilterPkt),
	)

	// update filter_pkt stub
	injectInsns(prog, filterPktFunc, insns)

	return nil
}

func (pf *packetFilter) clearSpecializedStubs(prog *ebpf.ProgramSpec) {
	clearSubprog(prog, pcapFilterL2StubSpecialized)
	clearSubprog(prog, pcapFilterL3StubSpecialized)
}

func (pf *packetFilter) clear(prog *ebpf.ProgramSpec) {
	pf.clearSpecializedStubs(prog)
	clearSubprog(prog, pcapFilterL2Stub)
	clearSubprog(prog, pcapFilterL3Stub)
	clearSubprog(prog, filterSkbFunc)
	clearSubprog(prog, filterXdpFunc)
	clearSubprog(prog, filterPktFunc)
}
