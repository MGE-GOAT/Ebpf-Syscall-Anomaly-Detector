# aya-tracer

A **Rust ([aya](https://aya-rs.dev)) port of `../tracer.py`** — the eBPF probe with **no bcc
dependency**. It attaches one program to `raw_syscalls:sys_enter`, counts per-`(pid, syscall)`
into a BPF hash map in-kernel, and the userspace loader drains that map once per second,
printing **one JSON line per window**:

```json
{"1888": {"0": 4, "1": 4, "35": 12, "202": 36, "281": 67}, "2207": {"41": 1, "42": 1, ...}}
```

That is the **same `{pid: {syscall: count}}` contract** the Python `tracer.py` emits, so this
binary is a drop-in replacement for the probe — the existing `features.py` / `detector.py`
ML pipeline can consume its stdout unchanged. The win over the bcc version: a single portable,
statically-analyzable binary with no Python/bcc/kernel-headers runtime, and a kernel program
checked by the BPF verifier (the `aya-tracer-ebpf` crate compiles to `bpfel-unknown-none`).

```text
aya-tracer-ebpf/   the in-kernel program (no_std) -> counts syscalls into a BPF_HASH
aya-tracer/        the userspace loader -> attaches it, drains + prints the map each second
aya-tracer-common/ shared types
```

**Run (needs root, like any eBPF loader):**
```shell
cargo build --release
sudo ./target/release/aya-tracer            # prints one JSON line of per-pid counts per second
# feed it straight into the Python detector:
sudo ./target/release/aya-tracer | python3 ../monitor_from_stdin.py   # (optional adapter)
```

Verified on `6.18.12+kali-amd64`: loads, attaches, and reports ~real per-process syscall mixes.

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
cargo build --package aya-tracer --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"rust-lld\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/aya-tracer` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, aya-tracer is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
