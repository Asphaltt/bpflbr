// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

const (
	lbrConfigFlagSuppressLbrIdx = 0 + iota
	lbrConfigFlagOutputStackIdx
)

type LbrConfig struct {
	Flags     uint32
	FilterPid uint32
	FnArgs    [MAX_BPF_FUNC_ARGS]FuncParamFlags
	FnArgsNr  uint32
}

func (cfg *LbrConfig) SetSuppressLbr(v bool) {
	if v {
		cfg.Flags |= 1 << lbrConfigFlagSuppressLbrIdx
	}
}

func (cfg *LbrConfig) SetOutputStack(v bool) {
	if v {
		cfg.Flags |= 1 << lbrConfigFlagOutputStackIdx
	}
}
