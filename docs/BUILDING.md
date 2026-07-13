# Building Horus

This document covers toolchain requirements, build targets, build flags, and how to run Horus under QEMU.

---

## Toolchain requirements

### Required (all builds)

| Tool | Purpose | Minimum version |
|---|---|---|
| GCC | C compiler and assembler driver | 9.x |
| GNU Binutils (`ld`, `objcopy`) | Linker and binary tools | 2.34 |
| GNU Make | Build system | 4.x |
| Rust + Cargo | Rust security core | stable (2021 edition) |

### Required for ISO and QEMU

| Tool | Purpose |
|---|---|
| `xorriso` | ISO image creation |
| `grub-pc-bin` / `grub-common` | GRUB2 Multiboot2 bootloader modules + `grub-mkrescue` |
| `mtools` | `mformat`, required by `grub-mkrescue` |
| `qemu-system-x86_64` | Emulation / boot tests |

### Installing on Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install \
    build-essential gcc binutils make \
    xorriso grub-pc-bin grub-common mtools \
    qemu-system-x86
```

### Installing Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup target add x86_64-unknown-none
```

---

## Build targets

### `make` / `make all`

Builds `kernel.elf` (x86-64). It compiles the Rust crate to `libhorus_shell.a`, compiles all C and assembly sources and the userspace binaries, and links everything with `linker64.ld`.

### `make run`

Builds `boot.iso` and launches QEMU: 512 MB RAM, `qemu64` CPU with AES/RDRAND/SMEP/SMAP, `-machine accel=kvm:tcg` (KVM when available), SDL display, and two serial ports. The console is on the socket serial at `localhost:4445` and **boot waits for a connection** (`wait=on`), so connect from another terminal:

```bash
make run
nc localhost 4445        # the interactive console
```

Default login: `user` / `password` (or `root` / `rootpass`).

### `make boot.iso`

Builds the bootable ISO without launching QEMU.

### `make clean`

Removes compiled objects, the Rust build cache, and `tools/mkheadered`. Does not remove `boot.iso` (untracked).

### `make test`

Runs the Rust unit tests (61 across the security core — see [TESTS.md](../TESTS.md)), then does a clean full build to verify compilation.

### Headless self-test targets

Each of these does a clean build with the relevant `*_SELFTEST` (or `SMP`) flag, boots headless under QEMU (`tools/smoke_test.sh`, software TCG — no host KVM needed), and asserts on a serial marker. `SMOKE_TIMEOUT=<seconds>` overrides the default 40 s.

| Target | Asserts |
|---|---|
| `make smoke` | Boots to the ring-3 login prompt with no fault/panic — the end-to-end boot check |
| `make smoke-elf` | Loads a real multi-segment static-PIE ELF at a randomised base; W^X per `PT_LOAD` and correct `R_386_RELATIVE` relocation (`ELF_SELFTEST: PASS`) |
| `make smoke-preempt` | The timer preempts and time-slices two non-yielding ring-3 tasks (`PREEMPT_SELFTEST: PASS`) |
| `make smoke-signal` | A task faults on purpose and its registered handler runs instead of being killed (`SIGNAL_SELFTEST: PASS`) |
| `make smoke-proc` | Ring-3 process control: exit + kill + spawn + exec + grant + signal + wait (+ fault-wait) (`PROC_SELFTEST: PASS …`) |
| `make smoke-fs` | The ring-3 `fs_server` + a client drive the full path over IPC (`FS_SELFTEST: PASS`); `make smoke-fs STORAGE=ata` runs it against a real ATA image |
| `make smoke-fs-persist` / `-perms` / `-conc` / `-wal` / `-large` | Filesystem persistence across reboot, per-file POSIX permissions, multi-client concurrency, the write-ahead journal replay, and large/double-indirect files (local) |
| `make smoke-init-fs` | The `init`-delegated `fs_server` driven by an automated client end-to-end (local) |
| `make smoke-newlib` | The newlib libc port over the POSIX fd layer (`NEWLIB_SELFTEST: PASS`) |
| `make smoke-smp` | Application processors come online and concurrently run scheduled tasks (`SMP_SELFTEST: PASS`); `SMP_CPUS=<n>` sets the core count |

### `make reproducible-build`

Clean-builds twice with a fixed `SOURCE_DATE_EPOCH` (2021-01-01 UTC) and fails if the two `kernel.elf`/`boot.iso` are not byte-for-byte identical; checksums are recorded to `.build.sha`.

### `make security`

Runs the security scanners (Semgrep, Trivy, gitleaks, cppcheck, flawfinder, `cargo-audit`) and emits a CycloneDX SBOM. Two of them are **blocking gates** in CI (and exit non-zero locally): **gitleaks** (committed secrets, scanned over full git history; reviewed false positives are allowlisted in `.gitleaks.toml`) and **Semgrep at ERROR severity**. The rest (Trivy, cppcheck, flawfinder, `cargo-audit`) are advisory. `make security-blocking` runs just the two gates; `make security-advisory` runs the rest.

---

## Build flags

Pass flags as `make FLAG=VALUE`.

| Flag | Default | Effect |
|---|---|---|
| `RUST_ENABLED` | `1` | If `0`, links C stub shims instead of the Rust library |
| `DEBUG_SHELL` | `0` | Enables the in-kernel debug shell (`#ifdef DEBUG_SHELL` code) |
| `MINIMAL_SECURE` | `0` | Strips optional kernel features for a smaller attack surface |
| `SMP` | `0` | Brings up the application processors (multi-core). `SMP_CPUS` sets the guest core count |
| `STORAGE_ATA` | `0` | Used by FS smoke/self-test targets to prefer the ATA path; at runtime the kernel always probes for a disk and falls back to the RAM vdisk when none is present. `BLOCKS_PER_DISK` sizes the volume |
| `ELF_SELFTEST` | `0` | Embeds a real static-PIE ELF and runs an in-kernel loader + W^X + relocation self-test at boot |
| `PREEMPT_SELFTEST` | `0` | Runs the two-task preemption self-test at boot |
| `SIGNAL_SELFTEST` | `0` | Runs the fault-signal self-test at boot |
| `PROC_SELFTEST` | `0` | Runs the ring-3 process-control self-test at boot |
| `FS_SELFTEST` | `0` | Runs the filesystem-server self-test at boot |
| `NEWLIB_SELFTEST` | `0` | Runs the newlib libc self-test at boot |
| `SMP_SELFTEST` | `0` | Runs the multi-core self-test at boot (implies `SMP=1`) |

> **Architecture:** Horus is x86-64 only. The kernel runs in 64-bit long mode; there is no 32-bit kernel build. The `DEBUG_SHELL=1` and `MINIMAL_SECURE=1` configurations are covered by a CI build matrix (the `altconfigs` job).

---

## Userspace programs

Userspace programs (`init`, `shell`, `fs_server`, `hello`, `captest`, plus the self-test drivers) are compiled as **static-PIE** 32-bit ELF binaries (`EM_386`, `ET_DYN`, linked with `userspace/pie.ld`) and run in a compatibility-mode segment beneath the 64-bit kernel. `do_spawn` picks a random page-aligned load base and the kernel's loader applies `R_386_RELATIVE` relocations there. The `mkheadered` tool prepends a custom program header the loader consumes. A flat-binary fallback remains for non-ELF images (loaded at the fixed base). Larger userspace programs link against the newlib libc port over a per-process POSIX fd layer, with `malloc`/`sbrk`/`brk`.

```bash
make userspace       # build all userspace binaries
```

The kernel image bundles the compiled userspace binaries, so rebuilding after changing userspace requires re-running `make` from the top level.

### newlib libc port

The newlib-linked programs (e.g. `hello_newlib`, exercised by `make smoke-newlib`)
need a `newlib/install/i686-elf` libc built for the userspace ABI. That tree is
**gitignored and built on demand** — no cross toolchain is required; newlib is built
with host `gcc` in freestanding `-m32` mode via thin `i686-elf-*` shims:

```bash
make newlib          # provision newlib/install (idempotent; skips if already built)
```

`scripts/build-newlib.sh` fetches a **checksum-pinned** newlib 4.5.0 source, builds
only the libc target (Horus supplies its own crt0/syscalls, so `libgloss` is neither
built nor needed), and adds the `stdio64.o` large-file stdio helpers the freestanding
config otherwise omits. Any newlib-headered compile depends on this automatically, so
a plain `make smoke-newlib` provisions it if missing. CI caches `newlib/install`
across runs (keyed on the build script), so it is built once.

---

## Rust crate details

The Rust crate is at `rust/`. It builds as a `staticlib` with `panic = "abort"`, `opt-level = "z"`, `lto = true`, `codegen-units = 1`, and `strip = true`. The resulting `libhorus_shell.a` is linked with `--whole-archive`. If Cargo or the `x86_64-unknown-none` target is missing, the build fails with an explicit error.

---

## Troubleshooting

**`grub-mkrescue failed`** — install `grub-pc-bin grub-common xorriso mtools` (`mtools` provides `mformat`).

**`cargo not found`** — install Rust via `rustup`.

**`rust target x86_64-unknown-none missing`** — `rustup target add x86_64-unknown-none`.

**`ERROR: rust/target/.../libhorus_shell.a missing`** — run `cargo build --release --manifest-path rust/Cargo.toml --target x86_64-unknown-none` and read the error.

**Linker errors about missing `rust_*` symbols** — ensure `RUST_ENABLED=1` (default) or that the crate built; pass `RUST_ENABLED=0` to use the C stub shims.

**QEMU shows nothing / serial only** — the boot configures GRUB's terminal to serial and waits for a console connection. Connect via `nc localhost 4445`.
