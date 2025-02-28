module github.com/leonhwangprojects/btrace

go 1.23.4

toolchain go1.24.0

require (
	github.com/Asphaltt/addr2line v0.1.1
	github.com/Asphaltt/mybtf v0.0.0-20250214152135-9b78e6e206e7
	github.com/cilium/ebpf v0.17.3
	github.com/fatih/color v1.18.0
	github.com/gobwas/glob v0.2.3
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/klauspost/compress v1.17.11
	github.com/knightsc/gapstone v4.0.1+incompatible
	github.com/leonhwangprojects/bice v0.1.1-0.20250227143508-96c8dbba466f
	github.com/spf13/pflag v1.0.5
	golang.org/x/exp v0.0.0-20241009180824-f66d83c29e7c
	golang.org/x/sync v0.8.0
)

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	rsc.io/c2go v0.0.0-20170620140410-520c22818a08 // indirect
)

require (
	github.com/ianlancetaylor/demangle v0.0.0-20240912202439-0a2b6291aafd // indirect
	golang.org/x/sys v0.30.0
)

replace github.com/knightsc/gapstone v4.0.1+incompatible => github.com/Asphaltt/gapstone v0.0.0-20241029140935-c5412a26abf7
