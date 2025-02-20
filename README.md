<!--
 Copyright 2024 Leon Hwang.
 SPDX-License-Identifier: Apache-2.0
-->

# bpflbr: an eBPF enhanced tool to trace some details of bpf prog with LBR

Here're some references to learn about LBR:

- [An introduction to last branch records](https://lwn.net/Articles/680985/).
- [Advanced usage of last branch records](https://lwn.net/Articles/680996/).
- [How to configure LBR (Last Branch Record) on Intel CPUs](https://sorami-chi.hateblo.jp/entry/2017/12/17/230000).
- [Intel® 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).

## bpflbr output example

The colorful output of `./bpflbr -v -k ip_rcv`:

![lbr example](./img/lbr%20stack%20example.png)

This is a function call stack from callers to callees based on LBR records provided by `bpf_get_branch_snapshot()`, [bpf: Introduce helper bpf_get_branch_snapshot](https://github.com/torvalds/linux/commit/856c02dbce4f).

## Dependencies

- *libcapstone-dev*: for disassembling machine native instructions.

## Build

With *libcapstone-dev*, build `bpflbr` by running:

```bash
make
```

## Usage

```bash
# ./bpflbr -h
Usage of bpflbr:
  -d, --disasm                disasm bpf prog or kernel function
  -B, --disasm-bytes uint     disasm bytes of kernel function, 0 to guess it automatically
      --disasm-intel-syntax   use Intel asm syntax for disasm, ATT asm syntax by default
      --filter-pid uint32     filter pid for tracing
  -k, --kfunc strings         filter kernel functions by shell wildcards way
      --kfunc-all-kmods       filter functions in all kernel modules
  -m, --mode string           mode of lbr tracing, exit or entry (default "exit")
  -o, --output string         output file for the result, default is stdout
      --output-stack          output function call stack
  -p, --prog strings          bpf prog info for bpflbr in format PROG[,PROG,..], PROG: PROGID[:<prog function name>], PROGID: <prog ID> or 'i/id:<prog ID>' or 'p/pinned:<pinned file>' or 't/tag:<prog tag>' or 'n/name:<prog full name>' or 'pid:<pid>'; all bpf progs will be traced if '*' is specified
      --suppress-lbr          suppress LBR perf event
  -v, --verbose               output verbose log
```

## Feature: dump LBR stack of kernel functions

`bpflbr` is able to dump LBR stack of kernel functions by `-k` option.

## Feature: dump jited insns of bpf prog

`bpflbr` is able to dump jited insns of bpf prog with att asm syntax:

```bash
# bpftool p
4483: kprobe  name kprobe_skb_3  tag 780473885099d6ae  gpl
      loaded_at 2024-10-29T14:46:13+0000  uid 0
      xlated 7544B  jited 3997B  memlock 12288B  map_ids 5449,5446,5447,5451,5450,5448,5444
      btf_id 6017

# ./bpflbr -p 4483 --disasm
; bpf/kprobe_pwru.c:532:0 PWRU_ADD_KPROBE(3)
0xffffffffc00c0e64: 0f 1f 44 00 00        nopl  (%rax, %rax)
0xffffffffc00c0e69: 66 90                 nop
0xffffffffc00c0e6b: 55                    pushq %rbp
0xffffffffc00c0e6c: 48 89 e5              movq  %rsp, %rbp
0xffffffffc00c0e6f: 48 81 ec 98 00 00 00  subq  $0x98, %rsp
...

# echo "If want to show intel asm syntax"
# ./bpflbr -p 4483 --disasm --disasm-intel-syntax
; bpf/kprobe_pwru.c:532:0 PWRU_ADD_KPROBE(3)
0xffffffffc00bde9c: 0f 1f 44 00 00        nop   dword ptr [rax + rax]
0xffffffffc00bdea1: 66 90                 nop
0xffffffffc00bdea3: 55                    push  rbp
0xffffffffc00bdea4: 48 89 e5              mov   rbp, rsp
0xffffffffc00bdea7: 48 81 ec 98 00 00 00  sub   rsp, 0x98
...
```

Colorful output (of `./bpflbr -d -k __netif_receive_skb_core -B 300`) by default:

![disasm example](./img/disasm%20example.png)

## Feature: trace target with fentry

By default, `bpflbr` traces targets with fexit. If you want to trace targets with fentry, you can use `--mode entry`.

It is really useful to trace the details before calling the target function/bpf-prog.

## Feature: dump function stack without LBR

As `bpflbr` is able to provide line info for an kernel address, it will provide line info for the addresses of function stack if dbgsym is available.

The colorful output of `./bpflbr -v -k ip_rcv --suppress-lbr --output-stack`:

![func stack example](./img/func%20stack%20example.png)

## Feature: output arguments and return value

`bpflbr` is able to output type, name and value of arguments, and type and value of return value.

![args and ret example](./img/func%20args%20and%20ret%20example.png)

## TODO list

- [ ] Develop `bpflbr` feature to trace userspace functions with uretprobe (**HELP WANTED**).

## Acknowledgments

- [cilium/ebpf](https://github.com/cilium/ebpf) for interacting with bpf subsystem.
- [daludaluking/addr2line](https://github.com/daludaluking/addr2line) for translating addresses to file and line number by parsing debug info from vmlinux.
- [knightsc/gapstone](https://github.com/knightsc/gapstone) for disassembling machine native instructions.

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.
