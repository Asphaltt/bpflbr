module github.com/Asphaltt/bpflbr

go 1.22.4

require (
	github.com/Asphaltt/addr2line v0.1.1
	github.com/cilium/ebpf v0.16.1-0.20241204125435-9895aae6467e
	github.com/gobwas/glob v0.2.3
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/klauspost/compress v1.17.11
	github.com/knightsc/gapstone v4.0.1+incompatible
	github.com/spf13/pflag v1.0.5
	golang.org/x/exp v0.0.0-20241009180824-f66d83c29e7c
	golang.org/x/sync v0.8.0
)

require (
	github.com/ianlancetaylor/demangle v0.0.0-20240912202439-0a2b6291aafd // indirect
	golang.org/x/sys v0.26.0
)

replace github.com/knightsc/gapstone v4.0.1+incompatible => github.com/Asphaltt/gapstone v0.0.0-20241029140935-c5412a26abf7
