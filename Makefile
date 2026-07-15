CC     = gcc
LD     = ld
AS     = gcc

export SOURCE_DATE_EPOCH ?= 1609459200

# Horus is x86-64 only. The kernel runs in 64-bit long mode; the ring-3
# userspace binaries are the sole 32-bit component (built in compatibility
# mode further down, USERSPACE_CFLAGS).
CFLAGS = -m64 -ffreestanding -fno-pic -fno-pie -fno-stack-protector \
         -Wall -Wextra -Wformat -Wformat-security -Werror=vla -O2 -pipe \
         -I src/include -I include -std=gnu99 -fno-builtin -mcmodel=kernel -frandom-seed=horus -fdebug-prefix-map=$(CURDIR)=/horus
ASFLAGS = -m64 -ffreestanding -fno-pic -fno-pie -x assembler-with-cpp -c
# The link script is swappable so VBOOT_ENFORCE builds can use a single-PT_LOAD
# layout (linker64_vboot.ld) whose loaded image is contiguous and deterministic
# to hash; the default/ship kernel keeps the three-segment linker64.ld.
LINKER_SCRIPT ?= linker64.ld
LDFLAGS = -T $(LINKER_SCRIPT) -m elf_x86_64 -nostdlib -static --build-id=none
RUST_TARGET ?= x86_64-unknown-none


OBJS = src/boot/multiboot.o \
       src/kernel/terminal.o \
       src/kernel/main.o \
       src/kernel/gdt.o \
       src/kernel/idt.o \
       src/kernel/paging.o \
       src/kernel/capability.o \
       src/kernel/scheduler.o \
       src/kernel/smp.o \
       src/kernel/aslr.o \
       src/kernel/syscall.o \
       src/kernel/kshell.o \
       src/kernel/loader.o \
       src/kernel/kaudit.o \
       src/kernel/kusers.o \
       src/kernel/syscall_fs.o \
       src/kernel/kspawn.o \
       src/kernel/selftest.o \
       src/kernel/verified_boot.o \
       src/kernel/syscall_ipc.o \
       src/kernel/ramfs.o \
       src/kernel/storage.o \
       src/kernel/crypto.o \
       src/kernel/ata.o

MINIMAL_SECURE ?= 0
ifeq ($(MINIMAL_SECURE),1)
CFLAGS += -DMINIMAL_SECURE=1
endif

# STORAGE_RING3_DISK=1 routes the kernel's live encrypted object store through the
# ring-3 disk_server (evicting the in-kernel ata.c driver from the primary disk).
# The storage stack runs on the in-kernel `storaged` coroutine so it can block on
# the ring-3 driver; see src/kernel/storaged.c. Off by default: the default build
# keeps the proven in-kernel ATA path byte-for-byte. USERSPACE_CFLAGS/embed wiring
# for disk_server is added under this flag further below.
STORAGE_RING3_DISK ?= 0
# STORAGED_SELFTEST=1 runs a boot-time proof of the storaged coroutine's mid-call
# save/restore across a yield (prints STORAGED_SELFTEST: PASS); it implies the
# storaged core. Gated off the ship kernel.
STORAGED_SELFTEST ?= 0
ifeq ($(STORAGED_SELFTEST),1)
CFLAGS  += -DSTORAGED_SELFTEST
STORAGE_RING3_DISK := 1
endif
ifeq ($(STORAGE_RING3_DISK),1)
CFLAGS  += -DSTORAGE_RING3_DISK
ASFLAGS += -DSTORAGE_RING3_DISK
OBJS    += src/kernel/storaged.o
endif

DEBUG_SHELL ?= 0
ifeq ($(DEBUG_SHELL),1)
CFLAGS += -DDEBUG_SHELL
endif

# ELF_SELFTEST=1 embeds a real multi-segment ELF and runs an in-kernel
# self-test of try_elf_load + W^X at boot (prints ELF_SELFTEST: PASS/FAIL to
# serial). Gated so the default/ship kernel is unaffected. ASFLAGS also gets
# the define so the gated .incbin in multiboot.S is included.
ELF_SELFTEST ?= 0
ifeq ($(ELF_SELFTEST),1)
CFLAGS  += -DELF_SELFTEST
ASFLAGS += -DELF_SELFTEST
ELF_SELFTEST_DEP = userspace/elftest.elf
endif

# PREEMPT_SELFTEST=1 embeds a flat userspace tracer and, at boot, spawns two
# copies of it and proves the timer preempts/time-slices them (prints
# PREEMPT_SELFTEST: PASS to serial). Gated so the default/ship kernel is
# unaffected. ASFLAGS also gets the define for the gated .incbin in multiboot.S.
PREEMPT_SELFTEST ?= 0
ifeq ($(PREEMPT_SELFTEST),1)
CFLAGS  += -DPREEMPT_SELFTEST
ASFLAGS += -DPREEMPT_SELFTEST
PREEMPT_SELFTEST_DEP = userspace/preempttest.bin
endif

# SIGNAL_SELFTEST=1 embeds a flat userspace payload that registers a fault
# handler then faults on purpose, and boots it to prove the handler runs
# instead of the task being killed (prints SIGNAL_SELFTEST: PASS to serial).
# Gated so the default/ship kernel is unaffected.
SIGNAL_SELFTEST ?= 0
ifeq ($(SIGNAL_SELFTEST),1)
CFLAGS  += -DSIGNAL_SELFTEST
ASFLAGS += -DSIGNAL_SELFTEST
SIGNAL_SELFTEST_DEP = userspace/sigtest.bin
endif

# STORAGE_ATA=1 makes the filesystem's block store the ATA disk (persistent)
# instead of the default in-RAM virtual disk. storage_init() probes the disk and
# formats-on-first-boot. Pair with a QEMU -drive (see `make run-ata`).
STORAGE_ATA ?= 0
ifeq ($(STORAGE_ATA),1)
CFLAGS  += -DSTORAGE_ATA
endif

# FS_SELFTEST=1 embeds the userspace fs_server and a client, spawns both at
# boot, and drives the filesystem end-to-end over IPC against the encrypted
# object store (prints FS_SELFTEST: PASS to serial). Gated off the ship kernel.
FS_SELFTEST ?= 0
ifeq ($(FS_SELFTEST),1)
CFLAGS  += -DFS_SELFTEST
ASFLAGS += -DFS_SELFTEST
FS_SELFTEST_DEP = userspace/fs_server.bin userspace/fsclient.bin
endif

# INIT_FS_SELFTEST=1 is the Phase-1 boot-time FS integration test: ring-3 init
# launches the userspace fs_server and provisions it purely by delegation
# (SYS_CAP_GRANT) instead of direct root-cnode installs, then launches the client
# that drives it. Proves the delegated server still serves end-to-end (the client
# prints FS_SELFTEST: PASS). fs_server is already always embedded; only the client
# needs adding. Gated off the ship kernel.
INIT_FS_SELFTEST ?= 0
ifeq ($(INIT_FS_SELFTEST),1)
CFLAGS  += -DINIT_FS_SELFTEST
ASFLAGS += -DINIT_FS_SELFTEST
INIT_FS_SELFTEST_DEP = userspace/fsclient.bin
endif

# INIT_DISK_SELFTEST=1 is the ring-3 driver proof: ring-3 init launches the
# userspace disk_server and delegates it the ATA secondary-channel device caps
# (CAP_IO_PORT x2 + CAP_IRQ 15). The server drives that disk from ring 3 via the
# TSS I/O bitmap + the IRQ->notification bridge, round-trips a scratch sector, and
# prints DISK_SERVER_SELFTEST: PASS (asserted by `make smoke-disk-server`). Gated
# off the ship kernel. CFLAGS reaches loader.c's embedded-binary table; ASFLAGS
# reaches the multiboot .incbin; the USERSPACE_CFLAGS half (init.c hook) is below.
INIT_DISK_SELFTEST ?= 0
ifeq ($(INIT_DISK_SELFTEST),1)
CFLAGS  += -DINIT_DISK_SELFTEST
ASFLAGS += -DINIT_DISK_SELFTEST
INIT_DISK_SELFTEST_DEP = userspace/disk_server.bin
endif

# PERSIST_SELFTEST=1 builds the FS self-test client in reboot-persistence mode: it
# writes a sentinel file on the first boot (prints PERSIST_SELFTEST: WROTE) and, on
# a later boot against the same disk image, reads it back and verifies it (prints
# PERSIST_SELFTEST: PASS). Reuses the FS_SELFTEST kernel driver (spawns server +
# client); pair with STORAGE_ATA=1 and drive it with the two-boot `make
# smoke-fs-persist`. The USERSPACE_CFLAGS half is applied after that variable is
# defined below.
PERSIST_SELFTEST ?= 0
ifeq ($(PERSIST_SELFTEST),1)
CFLAGS  += -DFS_SELFTEST -DPERSIST_SELFTEST
ASFLAGS += -DFS_SELFTEST
FS_SELFTEST_DEP = userspace/fs_server.bin userspace/fsclient.bin
endif

# PERM_SELFTEST=1 builds the FS self-test client in ownership/permission mode: it
# drives the fs_server's zero-trust access control end-to-end — root builds a
# scenario, then the client re-authenticates as a non-root user and the server
# enforces owner/group/other rwx against the caller's KERNEL-ATTESTED uid (a
# client cannot forge who it is). Reuses the FS_SELFTEST kernel driver (spawns
# server + client); the ephemeral RAM backend is sufficient.
PERM_SELFTEST ?= 0
ifeq ($(PERM_SELFTEST),1)
CFLAGS  += -DFS_SELFTEST -DPERM_SELFTEST
ASFLAGS += -DFS_SELFTEST
FS_SELFTEST_DEP = userspace/fs_server.bin userspace/fsclient.bin
endif

# CONC_SELFTEST=1 builds the FS self-test in multi-client concurrency mode: the
# kernel spawns one server and several client tasks that hammer it at once, each
# verifying it receives its own replies (SYS_IPC_REPLY_TO routes by the request's
# kernel-recorded sender). Reuses the FS_SELFTEST kernel driver + client binary.
CONC_SELFTEST ?= 0
ifeq ($(CONC_SELFTEST),1)
CFLAGS  += -DFS_SELFTEST -DCONC_SELFTEST
ASFLAGS += -DFS_SELFTEST
FS_SELFTEST_DEP = userspace/fs_server.bin userspace/fsclient.bin
endif

# WAL_CRASHTEST=1 builds the in-kernel journal crash-recovery test: boot 1 commits
# a write and halts before applying it; boot 2 replays the committed transaction
# at mount. Pure kernel (no userspace bins); driven by the two-boot smoke-fs-wal.
WAL_CRASHTEST ?= 0
ifeq ($(WAL_CRASHTEST),1)
CFLAGS  += -DWAL_CRASHTEST
ASFLAGS += -DWAL_CRASHTEST
endif

# BIGFILE_SELFTEST=1 builds the in-kernel large-file / double-indirect test: it
# writes blocks across the direct, single-indirect and double-indirect mapping
# regions of one inode and reads them back. Pure kernel (no userspace bins);
# driven by the single-boot smoke-fs-large.
BIGFILE_SELFTEST ?= 0
ifeq ($(BIGFILE_SELFTEST),1)
CFLAGS  += -DBIGFILE_SELFTEST
ASFLAGS += -DBIGFILE_SELFTEST
endif

# NEWLIB_SELFTEST=1 embeds hello_newlib (newlib + posix + malloc on Horus) and
# spawns it at boot to verify printf/sprintf/malloc/string ops work end-to-end
# (prints NEWLIB_SELFTEST: PASS to serial).  Gated off the ship kernel.
NEWLIB_SELFTEST ?= 0
ifeq ($(NEWLIB_SELFTEST),1)
CFLAGS  += -DNEWLIB_SELFTEST
ASFLAGS += -DNEWLIB_SELFTEST
NEWLIB_SELFTEST_DEP = userspace/hello_newlib.bin
endif

# NOTIFY_SELFTEST=1 embeds notifytest and, at boot, spawns it twice (a waiter and
# a sender) to prove the async SYS_NOTIFY / SYS_WAIT_NOTIFY badge round-trip works
# end-to-end (prints NOTIFY_SELFTEST: PASS to serial). Gated off the ship kernel.
NOTIFY_SELFTEST ?= 0
ifeq ($(NOTIFY_SELFTEST),1)
CFLAGS  += -DNOTIFY_SELFTEST
ASFLAGS += -DNOTIFY_SELFTEST
NOTIFY_SELFTEST_DEP = userspace/notifytest.bin
endif

# VBOOT_SELFTEST=1 exercises the Ed25519 verified-boot gate (verified_boot.c):
# at boot the kernel verifies a signed manifest against an embedded public key
# and halts if it fails. Proves the enforce-or-halt runtime boot-integrity
# mechanism (audit 3.3). VBOOT_TAMPER=1 corrupts the payload so the reject path
# (verification fails -> boot halts) is exercised too. Gated off the ship kernel.
VBOOT_SELFTEST ?= 0
ifeq ($(VBOOT_SELFTEST),1)
CFLAGS  += -DVBOOT_SELFTEST
VBOOT_TAMPER ?= 0
ifeq ($(VBOOT_TAMPER),1)
CFLAGS  += -DVBOOT_TAMPER
endif
endif

# VBOOT_ENFORCE=1 is the REAL verified boot: the kernel verifies its own loaded
# image against an Ed25519 signature over its bytes (anchored to an embedded key)
# and halts if it fails. Unlike VBOOT_SELFTEST (a fixed manifest), this refuses a
# tampered kernel image. It uses the single-PT_LOAD link script so the loaded
# image is contiguous/deterministic to hash, and compiles in the trust anchor
# from a generated header (tools/vboot_genkey.sh writes $(VBOOT_ANCHOR_DIR)/
# vboot_anchor.h; sign the built image with tools/vboot_sign.sh). See
# docs/BOOT_INTEGRITY.md and the `smoke-vboot-image` target.
VBOOT_ANCHOR_DIR ?= build
VBOOT_ENFORCE ?= 0
ifeq ($(VBOOT_ENFORCE),1)
CFLAGS       += -DVBOOT_ENFORCE -I$(VBOOT_ANCHOR_DIR)
LINKER_SCRIPT := linker64_vboot.ld
endif

# PROC_SELFTEST=1 embeds the proctest driver and, at boot, drives SYS_EXIT +
# SYS_KILL from ring 3, confirming both a self-exiting child and a killed child
# reach the dead state (prints PROC_SELFTEST: PASS). Gated off the ship kernel.
PROC_SELFTEST ?= 0
ifeq ($(PROC_SELFTEST),1)
CFLAGS  += -DPROC_SELFTEST
ASFLAGS += -DPROC_SELFTEST
PROC_SELFTEST_DEP = userspace/proctest.bin userspace/exectest.bin userspace/grantee.bin userspace/sigtarget.bin userspace/faulter.bin userspace/sigwaiter.bin userspace/argtest.bin userspace/preempttest.bin
endif

# SMP=1 brings up the application processors (multi-core) at boot: the BSP wakes
# every AP with a broadcast INIT-SIPI-SIPI and each walks itself to long mode via
# the real-mode trampoline (src/boot/ap_trampoline.S). Gated so the default build
# is single-CPU and byte-for-byte unaffected. Run under QEMU with -smp N (see
# `make smoke-smp`). ASFLAGS also gets the define so the gated .incbin of the
# trampoline blob in multiboot.S is included.
# SMP_SELFTEST=1 implies SMP=1 and, at boot, spawns a pool of forever-looping
# workers and proves the application processors pull and run them concurrently
# (prints SMP_SELFTEST: PASS to serial). Drives `make smoke-smp`.
SMP_SELFTEST ?= 0
ifeq ($(SMP_SELFTEST),1)
SMP := 1
CFLAGS  += -DSMP_SELFTEST
ASFLAGS += -DSMP_SELFTEST
SMP_SELFTEST_DEP = userspace/preempttest.bin
endif

SMP ?= 0
ifeq ($(SMP),1)
CFLAGS  += -DSMP
ASFLAGS += -DSMP
AP_TRAMPOLINE_DEP = src/boot/ap_trampoline.bin
endif

OBJS += src/boot/entry64.o
OBJS += src/kernel/lowlevel64.o

all: kernel.elf

RUST_ENABLED := 1
ifneq ($(origin RUST_ENABLED),command line)
RUST_ENABLED := 1
endif

ifeq ($(RUST_ENABLED),1)
  ifeq ($(shell command -v cargo >/dev/null 2>&1 && echo yes),)
    $(error cargo not found. Install Rust: rustup target add $(RUST_TARGET))
  endif
  ifeq ($(shell rustup target list --installed 2>/dev/null | grep -q $(RUST_TARGET) && echo yes),)
    $(error rust target $(RUST_TARGET) missing: rustup target add $(RUST_TARGET))
  endif
endif

RUST_LIB := rust/target/$(RUST_TARGET)/release/libhorus_shell.a

.PHONY: rust
rust:
	@cargo build --release --manifest-path rust/Cargo.toml --target $(RUST_TARGET)
	@test -f $(RUST_LIB) || (echo "ERROR: $(RUST_LIB) missing"; exit 1)

with-rust:
	$(MAKE) RUST_ENABLED=1

ifeq ($(RUST_ENABLED),1)
RUST_EXTRA_OBJS := src/kernel/rust_memory_stubs.o
else
RUST_EXTRA_OBJS := src/kernel/rust_shims.o
endif

kernel.elf: $(RUST_LIB) $(OBJS) $(RUST_EXTRA_OBJS)
ifeq ($(RUST_ENABLED),1)
	$(LD) $(LDFLAGS) -o $@ --whole-archive $(RUST_LIB) --no-whole-archive $(OBJS) $(RUST_EXTRA_OBJS)
else
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(RUST_EXTRA_OBJS)
endif

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(AS) $(ASFLAGS) $< -o $@

src/boot/multiboot.o: userspace/shell.bin userspace/init.bin userspace/hello.bin userspace/captest.bin userspace/fs_server.bin $(ELF_SELFTEST_DEP) $(PREEMPT_SELFTEST_DEP) $(SIGNAL_SELFTEST_DEP) $(FS_SELFTEST_DEP) $(INIT_FS_SELFTEST_DEP) $(INIT_DISK_SELFTEST_DEP) $(NEWLIB_SELFTEST_DEP) $(NOTIFY_SELFTEST_DEP) $(AP_TRAMPOLINE_DEP) $(SMP_SELFTEST_DEP) $(PROC_SELFTEST_DEP)

# AP startup trampoline: 16-bit real-mode code assembled with -m32 (the .code16
# directive emits the right encodings) and linked flat at its SIPI load address
# 0x8000, then emitted as a raw binary that multiboot.S embeds via .incbin.
src/boot/ap_trampoline.o: src/boot/ap_trampoline.S
	$(CC) -m32 -ffreestanding -fno-pic -x assembler-with-cpp -c $< -o $@
src/boot/ap_trampoline.bin: src/boot/ap_trampoline.o
	$(LD) -m elf_i386 -Ttext=0x8000 --oformat binary -o $@ $<

src/kernel/rust_shims.o: src/kernel/rust_shims.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/rust_stubs.o: src/kernel/rust_stubs.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/rust_memory_stubs.o: src/kernel/rust_memory_stubs.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/storage.o: src/kernel/storage.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/crypto.o: src/kernel/crypto.c
	$(CC) $(CFLAGS) -msse2 -maes -c $< -o $@

src/kernel/ata.o: src/kernel/ata.c
	$(CC) $(CFLAGS) -c $< -o $@

ifeq ($(RUST_ENABLED),1)
$(RUST_LIB): rust/src/lib.rs rust/Cargo.toml rust/src/capability.rs rust/src/crypto.rs rust/src/memory.rs
	@cargo build --locked --release --manifest-path rust/Cargo.toml --target $(RUST_TARGET) || cargo build --release --manifest-path rust/Cargo.toml --target $(RUST_TARGET)
	@test -f $(RUST_LIB) || (echo "ERROR: $(RUST_LIB) missing"; exit 1)
endif

run: kernel.elf
	@$(MAKE) --no-print-directory boot.iso
	@echo "Console on serial: connect with  nc localhost 4445  (boot waits for it)."
	qemu-system-x86_64 -m 512M -cpu qemu64,+aes,+rdrand,+smep,+smap \
		-machine accel=kvm:tcg -display sdl -vga std \
		-chardev socket,id=char0,port=4445,host=localhost,server=on,wait=on \
		-serial chardev:char0 \
		-serial tcp:localhost:4444,server,nowait,nodelay \
		-monitor none -device isa-debug-exit,iobase=0x604,iosize=0x04 \
		-net none -no-reboot -no-shutdown -cdrom boot.iso

# run-tty: interactive kernel straight in the current terminal — NO graphical
# window and NO `nc`. COM1 (the ring-3 shell) is wired to this terminal's
# stdin/stdout via `-serial mon:stdio`, so you get the `horus login:` prompt
# right here. Log in as  root / rootpass . Quit QEMU with  Ctrl-A x
# (Ctrl-A c toggles the QEMU monitor). Contrast with `run`, which opens an SDL
# window and parks the console on a socket you must `nc localhost 4445` into.
#
# Forces a fresh DEFAULT kernel first: a `make smoke-vboot*` run leaves a
# VBOOT_SELFTEST kernel.elf that halts on purpose ("rejected -- halting boot")
# and never reaches the shell, and it looks up-to-date to make. Rebuilding the
# object + ELF sidesteps that trap without a full `clean`.
.PHONY: run-tty
run-tty:
	@rm -f src/kernel/verified_boot.o kernel.elf boot.iso
	@$(MAKE) --no-print-directory boot.iso
	@echo "== Horus: login 'root' / 'rootpass'.  Quit QEMU: Ctrl-A x =="
	qemu-system-x86_64 -m 512M -cpu qemu64,+aes,+rdrand,+smep,+smap -accel tcg \
		-display none -no-reboot -no-shutdown \
		-device isa-debug-exit,iobase=0x604,iosize=0x04 \
		-serial mon:stdio -net none -cdrom boot.iso


boot.iso: kernel.elf grub.cfg
	@rm -rf isofiles
	@mkdir -p isofiles/boot/grub
	@cp kernel.elf isofiles/boot/kernel.elf
	@cp kernel.elf isofiles/kernel.elf
	@cp grub.cfg isofiles/boot/grub/grub.cfg
	@grub-mkrescue -o $@ isofiles 2>&1 || (echo "grub-mkrescue failed (install grub-pc-bin xorriso)" && exit 1)
	@rm -rf isofiles

clean: userspace-clean
	rm -f kernel.elf src/boot/*.o src/boot/*.bin src/kernel/*.o src/kernel/rust_*.o
	rm -rf rust/target

clean-rust:
	rm -rf rust/target

iso: kernel.elf
	@mkdir -p iso/boot/grub && cp kernel.elf iso/boot/ && cp grub.cfg iso/boot/grub/grub.cfg
	@grub-mkrescue -o horus.iso iso 2>/dev/null || true

# Userspace is built position-independent (-fPIE): the shipped binaries are
# linked as static-PIE ELFs (ET_DYN) and loaded by the kernel at a randomized
# base (ASLR), which relocates them. GCC's GOTOFF addressing keeps freestanding
# code position-independent (usually zero dynamic relocations). The gated flat
# self-test payloads (preempttest/sigtest) reuse the same objects linked as a
# fixed-base flat image; PIE objects link cleanly at a fixed address too.
USERSPACE_CFLAGS = -m32 -ffreestanding -fPIE -fno-plt -fno-stack-protector \
                   -Wall -Wextra -O2 -I include -std=gnu99 -fno-builtin
# init.c switches to the delegated-fs-server boot path under this flag, so the
# userspace build of init must see it too (kernel CFLAGS alone won't reach it).
ifeq ($(INIT_FS_SELFTEST),1)
USERSPACE_CFLAGS += -DINIT_FS_SELFTEST
endif
ifeq ($(INIT_DISK_SELFTEST),1)
USERSPACE_CFLAGS += -DINIT_DISK_SELFTEST
endif
ifeq ($(PERSIST_SELFTEST),1)
USERSPACE_CFLAGS += -DPERSIST_SELFTEST
endif
ifeq ($(PERM_SELFTEST),1)
USERSPACE_CFLAGS += -DPERM_SELFTEST
endif
ifeq ($(CONC_SELFTEST),1)
USERSPACE_CFLAGS += -DCONC_SELFTEST
endif

userspace/%.o: userspace/%.c
	$(CC) $(USERSPACE_CFLAGS) -c $< -o $@

# Static-PIE (ET_DYN) link for the shipped, ASLR-loaded binaries.
# malloc.o is always linked so any binary can call malloc/free without
# extra Makefile rules.
MALLOC_OBJ = userspace/malloc.o
userspace/%.pie.elf: userspace/%.o $(MALLOC_OBJ) userspace/pie.ld
	$(LD) -m elf_i386 -pie -T userspace/pie.ld -o $@ $< $(MALLOC_OBJ)

# Newlib-linked PIE ELFs: compiled with newlib headers, linked against libc.a.
# crt0.o provides _start → posix_init() → main().
NEWLIB_INC      = newlib/install/i686-elf/include
NEWLIB_LIB      = newlib/install/i686-elf/lib
NEWLIB_CFLAGS   = $(USERSPACE_CFLAGS) -I $(NEWLIB_INC)
NEWLIB_GLUE_OBJS = userspace/newlib_glue.o userspace/newlib_glue64.o \
                   userspace/posix.o userspace/crt0.o

# Provision the newlib libc port on demand (idempotent, checksum-pinned, cached).
# The install tree (newlib/install) is gitignored and built by
# scripts/build-newlib.sh — host gcc in freestanding -m32 mode, no cross toolchain.
# Every newlib-headered compile below takes $(NEWLIB_INC)/stdio.h as an order-only
# prerequisite, so a missing install is built automatically; `make newlib` builds it
# explicitly (the smoke-newlib CI job caches newlib/install across runs).
.PHONY: newlib
newlib: $(NEWLIB_INC)/stdio.h
$(NEWLIB_INC)/stdio.h:
	@$(SHELL) scripts/build-newlib.sh

userspace/newlib_glue.o: userspace/newlib_glue.c | $(NEWLIB_INC)/stdio.h
	$(CC) $(NEWLIB_CFLAGS) -c $< -o $@

userspace/newlib_glue64.o: userspace/newlib_glue64.c | $(NEWLIB_INC)/stdio.h
	$(CC) $(NEWLIB_CFLAGS) -c $< -o $@

userspace/crt0.o: userspace/crt0.c
	$(CC) $(USERSPACE_CFLAGS) -c $< -o $@

userspace/hello_newlib.o: userspace/hello_newlib.c | $(NEWLIB_INC)/stdio.h
	$(CC) $(NEWLIB_CFLAGS) -c $< -o $@

userspace/hello_newlib.pie.elf: userspace/hello_newlib.o $(NEWLIB_GLUE_OBJS) \
                                userspace/malloc.o userspace/pie.ld
	$(LD) -m elf_i386 -pie -T userspace/pie.ld -o $@ \
	    userspace/crt0.o userspace/hello_newlib.o userspace/newlib_glue.o \
	    userspace/newlib_glue64.o userspace/posix.o userspace/malloc.o \
	    -L$(NEWLIB_LIB) -lc

userspace/hello_newlib.bin: userspace/hello_newlib.pie.elf tools/mkheadered
	@./tools/mkheadered $< $@ "hello_newlib"

# Fixed-base flat link (used by the gated selftest payloads that are embedded
# raw and loaded at USER_AREA_BASE without relocation).
userspace/%.elf: userspace/%.o
	$(LD) -m elf_i386 -Ttext=0x400000 -o $@ $<

# The ELF-loader self-test image is linked with a custom script that produces
# distinct page-aligned R+X / R+W / R PT_LOAD segments (explicit rule wins over
# the pattern rule above). It is kept as a real ELF, never objcopy-flattened.
userspace/elftest.elf: userspace/elftest.o userspace/elftest.ld
	$(LD) -m elf_i386 -pie -T userspace/elftest.ld -o $@ $<

userspace/%.raw: userspace/%.elf
	objcopy -O binary $< $@

tools/mkheadered: tools/mkheadered.c
	$(CC) -o $@ $<

# Shipped binaries: HORU-wrap the static-PIE ELF (real ELF payload, so the
# kernel's do_spawn routes it through try_elf_load with ASLR + relocations).
SHIPPED_PIE_BINS = userspace/shell.bin userspace/init.bin userspace/hello.bin \
                   userspace/fs_server.bin userspace/captest.bin
$(SHIPPED_PIE_BINS): userspace/%.bin: userspace/%.pie.elf tools/mkheadered
	@./tools/mkheadered $< $@ "$*"

# PIE test-only binaries (not shipped): built via the same static-PIE path as
# the shipped bins, but kept out of $(SHIPPED_PIE_BINS)/`userspace`. proctest is
# PIE (not flat) because it dereferences .rodata string literals, which on 32-bit
# -fPIE go through the GOT and only resolve once try_elf_load applies the
# R_386_RELATIVE relocations — the flat load path does not.
PIE_TEST_BINS = userspace/fsclient.bin userspace/proctest.bin userspace/exectest.bin userspace/grantee.bin userspace/sigtarget.bin userspace/faulter.bin userspace/sigwaiter.bin userspace/argtest.bin userspace/notifytest.bin userspace/disk_server.bin
$(PIE_TEST_BINS): userspace/%.bin: userspace/%.pie.elf tools/mkheadered
	@./tools/mkheadered $< $@ "$*"

# execve-from-fd self-test: embed a real, already-built program image (hello) as
# a C byte array so proctest can hand it to SYS_SPAWN_IMAGE — the same bytes a
# client would read from a file. Generated from the .bin with coreutils only
# (od/tr/grep/paste, present in CI); a PROC_SELFTEST-only prerequisite of proctest.
userspace/hello_image.h: userspace/hello.bin
	@printf 'static const unsigned char hello_image[] = {' > $@
	@od -An -v -tu1 $< | tr -s ' ' '\n' | grep -v '^$$' | paste -sd, >> $@
	@printf '};\nstatic const unsigned hello_image_len = sizeof(hello_image);\n' >> $@

userspace/proctest.o: userspace/hello_image.h

# Flat self-test payloads: HORU-wrap the objcopy'd raw image (loaded flat).
userspace/%.bin: userspace/%.raw tools/mkheadered
	@name="$$(basename $@ .bin)"; ./tools/mkheadered $< $@ "$$name"

userspace: $(SHIPPED_PIE_BINS)

userspace-clean:
	rm -f userspace/*.o userspace/*.elf userspace/*.pie.elf userspace/*.raw userspace/*.bin userspace/*_image.h tools/mkheadered

# Build the kernel with the gated ELF-loader self-test, boot it headless, and
# require the in-kernel self-test to report PASS on serial (in addition to the
# normal boot reaching userspace). Runtime-verifies the try_elf_load + W^X path.
.PHONY: smoke-elf
smoke-elf:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory ELF_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='ELF_SELFTEST: PASS' \
		FAIL_MARKER='ELF_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated preemption self-test, boot headless, and require the
# in-kernel test to report PASS -- runtime proof that the timer time-slices two
# non-yielding ring-3 tasks.
.PHONY: smoke-preempt
smoke-preempt:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PREEMPT_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='PREEMPT_SELFTEST: PASS' \
		FAIL_MARKER='PREEMPT_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated signal self-test, boot headless, and require the handler
# to run on a deliberate fault -- runtime proof that a ring-3 fault is delivered
# to a registered handler instead of killing the task.
.PHONY: smoke-signal
smoke-signal:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SIGNAL_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='SIGNAL_SELFTEST: PASS' \
		FAIL_MARKER='SIGNAL_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated filesystem self-test, boot headless, and require the
# client to report PASS -- runtime proof that the userspace fs_server serves a
# client over IPC against the kernel's encrypted object store. `STORAGE=ata`
# runs the same test against a real ATA disk image (the persistent backend).
ifeq ($(STORAGE),ata)
SMOKE_FS_FLAGS = STORAGE_ATA=1
SMOKE_FS_ENV   = SMOKE_DISK=horus-fs.img
SMOKE_FS_PREP  = dd if=/dev/zero of=horus-fs.img bs=512 count=$(BLOCKS_PER_DISK) status=none
BLOCKS_PER_DISK ?= 1024
else
SMOKE_FS_FLAGS =
SMOKE_FS_ENV   =
SMOKE_FS_PREP  = true
endif
.PHONY: smoke-fs
smoke-fs:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FS_SELFTEST=1 $(SMOKE_FS_FLAGS)
	@$(MAKE) --no-print-directory boot.iso
	@$(SMOKE_FS_PREP)
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 $(SMOKE_FS_ENV) REQUIRE_MARKER='FS_SELFTEST: PASS' \
		FAIL_MARKER='FS_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Boot-time FS integration test: ring-3 init brings up the fs_server by delegation
# (SYS_CAP_GRANT) and the delegated server serves the client end-to-end. Reuses
# the fs client's PASS/FAIL markers ("INIT_FS_SELFTEST: FAIL ..." also matches the
# FAIL substring). `STORAGE=ata` runs it against the persistent ATA backend.
.PHONY: smoke-init-fs
smoke-init-fs:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory INIT_FS_SELFTEST=1 $(SMOKE_FS_FLAGS)
	@$(MAKE) --no-print-directory boot.iso
	@$(SMOKE_FS_PREP)
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 $(SMOKE_FS_ENV) REQUIRE_MARKER='FS_SELFTEST: PASS' \
		FAIL_MARKER='FS_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Ring-3 driver proof: ring-3 init launches the disk_server and delegates it the
# ATA secondary-channel device caps; the server drives that disk from ring 3 —
# capability-gated port I/O (TSS I/O bitmap) plus the kernel's IRQ->notification
# bridge — round-trips a scratch sector, and prints DISK_SERVER_SELFTEST: PASS.
# The test disk (SMOKE_DISK2, IDE index 1 = primary SLAVE) is driven by the ring-3
# server; the kernel's object store only touches the primary master, so the two
# never contend. Single boot; a fresh zeroed image is fine (server writes, reads).
.PHONY: smoke-storaged
# Phase-1 proof of the storaged coroutine: kswitch saves/restores a mid-call kernel
# stack across a yield (prints STORAGED_SELFTEST: PASS at boot). No disk needed.
smoke-storaged:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory STORAGED_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='STORAGED_SELFTEST: PASS' FAIL_MARKER='STORAGED_SELFTEST: FAIL' \
		tools/smoke_test.sh boot.iso

.PHONY: smoke-disk-server
smoke-disk-server:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory INIT_DISK_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@dd if=/dev/zero of=disk2.img bs=512 count=1024 status=none
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK2=disk2.img \
		REQUIRE_MARKER='DISK_SERVER_SELFTEST: PASS' FAIL_MARKER='DISK_SERVER_SELFTEST: FAIL' \
		tools/smoke_test.sh boot.iso

# Reboot-survival test: boot twice against ONE persistent ATA disk image. Boot 1
# writes a sentinel file (PERSIST_SELFTEST: WROTE); boot 2, on the same image,
# reads it back and verifies it byte-for-byte (PERSIST_SELFTEST: PASS) — proving
# the encrypted object store and its per-block crypto metadata (nonces/tags)
# survive a reboot. Argon2id KEK derivation + format-on-first-boot run under TCG,
# so allow a generous timeout.
PERSIST_BLOCKS  ?= 1024
PERSIST_TIMEOUT ?= 300
.PHONY: smoke-fs-persist
smoke-fs-persist:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PERSIST_SELFTEST=1 STORAGE_ATA=1
	@$(MAKE) --no-print-directory boot.iso
	@dd if=/dev/zero of=persist.img bs=512 count=$(PERSIST_BLOCKS) status=none
	@echo "[persist] boot 1/2 — write sentinel to a fresh encrypted disk"
	@SMOKE_TIMEOUT=$(PERSIST_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK=persist.img \
		REQUIRE_MARKER='PERSIST_SELFTEST: WROTE' FAIL_MARKER='PERSIST_SELFTEST: FAIL' \
		tools/smoke_test.sh boot.iso
	@echo "[persist] boot 2/2 — verify the file survived (same disk image)"
	@SMOKE_TIMEOUT=$(PERSIST_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK=persist.img \
		REQUIRE_MARKER='PERSIST_SELFTEST: PASS' FAIL_MARKER='PERSIST_SELFTEST: FAIL' \
		tools/smoke_test.sh boot.iso
	@echo "[persist] PASS — encrypted file survived a reboot"

# Zero-trust ownership & permissions: root builds a scenario, the client then
# re-authenticates as a non-root user and the fs_server enforces owner/group/other
# rwx against the caller's kernel-attested uid (denied reads/writes/creates/chmod
# it isn't entitled to; owner and root allowed). Proves a client cannot access
# what its real uid disallows.
.PHONY: smoke-fs-perms
smoke-fs-perms:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PERM_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='PERM_SELFTEST: PASS' \
		FAIL_MARKER='PERM_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Multi-client concurrency: one fs_server, several clients hammering it at once,
# each verifying it receives its own replies (no cross-talk, no lost replies).
# The coordinator prints CONC_SELFTEST: PASS only after every worker completes.
# Journal crash-recovery: boot QEMU twice against one disk image. Boot 1 commits a
# write to the journal and halts BEFORE applying it (simulating a crash); boot 2
# replays the committed transaction at mount and confirms the write survived —
# proving redo recovery (and that a mid-write crash can't brick or corrupt the fs).
.PHONY: smoke-fs-wal
smoke-fs-wal:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory WAL_CRASHTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@dd if=/dev/zero of=wal.img bs=512 count=$(PERSIST_BLOCKS) status=none
	@echo "[wal] boot 1/2 — commit a write, then crash before applying it"
	@SMOKE_TIMEOUT=$(PERSIST_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK=wal.img \
		REQUIRE_MARKER='WAL_CRASHTEST: crashed-after-commit' FAIL_MARKER='WAL_CRASHTEST: FAIL' \
		tools/smoke_test.sh boot.iso
	@echo "[wal] boot 2/2 — recover the committed transaction, verify the data"
	@SMOKE_TIMEOUT=$(PERSIST_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK=wal.img \
		REQUIRE_MARKER='WAL_CRASHTEST: PASS' FAIL_MARKER='WAL_CRASHTEST: FAIL' \
		tools/smoke_test.sh boot.iso
	@echo "[wal] PASS — committed transaction replayed after a crash"

.PHONY: smoke-fs-conc
smoke-fs-conc:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CONC_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='CONC_SELFTEST: PASS' \
		FAIL_MARKER='CONC_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

.PHONY: smoke-newlib
smoke-newlib:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NEWLIB_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='NEWLIB_SELFTEST: PASS' \
		FAIL_MARKER='NEWLIB_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated large-file self-test, boot headless, and require the
# in-kernel test to report PASS -- runtime proof that a single inode can map
# blocks through the double-indirect region (large files) on the encrypted
# object store, and that freeing the whole tree succeeds.
.PHONY: smoke-fs-large
smoke-fs-large:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory BIGFILE_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='BIGFILE_SELFTEST: PASS' \
		FAIL_MARKER='BIGFILE_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated SMP self-test, boot headless under -smp 4, and require the
# in-kernel test to report PASS -- runtime proof that the application processors
# come online and concurrently run scheduled user tasks. SMP_CPUS drives QEMU's
# core count.
SMP_CPUS ?= 4
.PHONY: smoke-smp
smoke-smp:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SMP_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 SMP_CPUS=$(SMP_CPUS) REQUIRE_MARKER='SMP_SELFTEST: PASS' \
		FAIL_MARKER='SMP_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated process-control self-test, boot headless, and require the
# in-kernel driver to report PASS -- runtime proof that SYS_EXIT and SYS_KILL
# terminate tasks (a self-exiting child and a killed child both reach dead).
.PHONY: smoke-proc
smoke-proc:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='PROC_SELFTEST: PASS exit+kill+spawn+exec+grant+image+altstack+signal' \
		FAIL_MARKER='PROC_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated notification self-test, boot headless, and require the
# in-kernel waiter to report PASS -- runtime proof that SYS_NOTIFY delivers a
# badge to a task blocked in SYS_WAIT_NOTIFY (async notifications end-to-end).
.PHONY: smoke-notify
smoke-notify:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NOTIFY_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='NOTIFY_SELFTEST: PASS' \
		FAIL_MARKER='NOTIFY_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Ed25519 verified-boot gate (audit 3.3, runtime half). Two headless boots:
#  (1) ACCEPT: a valid signature over the signed manifest authorizes the boot.
#  (2) REJECT: a tampered manifest fails verification and the kernel halts.
# Both assert their marker on serial; the from-scratch Ed25519 verifier is
# additionally validated against RFC 8032 + an OpenSSL signature in `cargo test`.
.PHONY: smoke-vboot
smoke-vboot:
	@echo "== verified-boot ACCEPT: valid manifest signature -> boot authorized =="
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory VBOOT_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='VBOOT_SELFTEST: PASS manifest signature verified' \
		FAIL_MARKER='VBOOT_SELFTEST: FAIL' tools/smoke_test.sh boot.iso
	@echo "== verified-boot REJECT: tampered manifest -> halt =="
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory VBOOT_SELFTEST=1 VBOOT_TAMPER=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='VBOOT_SELFTEST: PASS tampered manifest rejected' \
		FAIL_MARKER='VBOOT_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# REAL-IMAGE verified boot (audit 3.3, Phase B anchoring). Unlike smoke-vboot
# (a fixed embedded manifest), this signs the ACTUAL kernel image and proves the
# machine refuses a tampered one. An ephemeral Ed25519 key is generated (never
# committed), its public half compiled in as the trust anchor, the built image
# signed over its own bytes, and two headless boots run:
#  (1) ACCEPT: the untouched signed image verifies -> boot authorized (continues).
#  (2) REJECT: one flipped byte in the signed region -> verification fails -> halt.
.PHONY: smoke-vboot-image
smoke-vboot-image:
	@echo "== verified-boot (real image) ACCEPT: signed kernel -> boot authorized =="
	@$(MAKE) --no-print-directory clean
	@mkdir -p $(VBOOT_ANCHOR_DIR)
	@bash tools/vboot_genkey.sh $(VBOOT_ANCHOR_DIR)/vboot_priv.pem $(VBOOT_ANCHOR_DIR)/vboot_anchor.h
	@$(MAKE) --no-print-directory VBOOT_ENFORCE=1 kernel.elf
	@bash tools/vboot_sign.sh kernel.elf $(VBOOT_ANCHOR_DIR)/vboot_priv.pem
	@$(MAKE) --no-print-directory VBOOT_ENFORCE=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='VBOOT_ENFORCE: PASS kernel image signature verified' \
		FAIL_MARKER='VBOOT_ENFORCE: FAIL' tools/smoke_test.sh boot.iso
	@echo "== verified-boot (real image) REJECT: tampered kernel -> halt =="
	@bash tools/vboot_tamper.sh kernel.elf
	@$(MAKE) --no-print-directory VBOOT_ENFORCE=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='VBOOT_ENFORCE: FAIL kernel image signature invalid' \
		FAIL_MARKER='VBOOT_ENFORCE: PASS' tools/smoke_test.sh boot.iso

# Scripted integration session: build the shipped kernel and drive the *real*
# ring-3 shell over serial (login, identity, and a capability-gated admin op
# allowed for root but denied for a standard user), asserting on the responses.
# Unlike the marker self-tests, nothing is compiled into the kernel — it is a
# black-box test of the actual login/shell/syscall path. Prints SESSION_TEST: PASS.
.PHONY: smoke-session
smoke-session:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory boot.iso
	@python3 tools/session_test.py boot.iso

.PHONY: test
test:
	@cargo test --manifest-path rust/Cargo.toml --release || true
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory all

# Headless QEMU smoke-boot test: boot the kernel and confirm it reaches the
# ring-3 shell banner with no fault/panic on serial. SMOKE_TIMEOUT overrides
# the wait (seconds).
SMOKE_TIMEOUT ?= 40
.PHONY: smoke
smoke: boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) tools/smoke_test.sh boot.iso

.PHONY: reproducible-build verify-build
reproducible-build:
	@rm -f kernel.elf boot.iso
	@SOURCE_DATE_EPOCH=1609459200 $(MAKE) --no-print-directory clean all
	@sha256sum kernel.elf boot.iso > .build.sha 2>/dev/null || true
	@echo "Reproducible build recorded."

verify-build: reproducible-build
	@echo "Verify complete."

.PHONY: security security-blocking security-advisory security-install install-trivy install-gitleaks semgrep trivy gitleaks cppcheck flawfinder cargo-audit

# Full local scan: the blocking gates first (so a real finding stops you before
# the advisory noise), then the advisory scanners.
security: security-blocking security-advisory
	@echo ""
	@echo "✅ Security scan complete."
	@echo "   Review all output above for findings."
	@echo "   High-severity issues should be fixed before merging."

# BLOCKING gates (CI fails on these): committed secrets and Semgrep ERROR-level
# findings. `make gitleaks` and `make semgrep` both exit non-zero on a hit.
security-blocking: semgrep gitleaks

# Advisory scanners: reported for review but never fail the build.
security-advisory: trivy cppcheck flawfinder cargo-audit

# Pinned tool versions + SHA-256 digests, matching the CI security job so a local
# `make security` installs exactly what CI gates with — and NEVER via an
# unverified `curl | sh` (the previous local installer piped a remote script into
# a root shell; the Trivy digest below is the same one ci.yml verifies).
TRIVY_VERSION    := 0.72.0
TRIVY_SHA256     := bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea
GITLEAKS_VERSION := 8.21.0
GITLEAKS_SHA256  := 6c3a240509647225997d31df06e872350e1c0fe2fb85d323ae29a9fef0012586

install-trivy:
	@echo "=== installing Trivy $(TRIVY_VERSION) (pinned, SHA-256 verified) ==="
	curl -sfL https://github.com/aquasecurity/trivy/releases/download/v$(TRIVY_VERSION)/trivy_$(TRIVY_VERSION)_Linux-64bit.tar.gz -o /tmp/trivy.tar.gz
	echo "$(TRIVY_SHA256)  /tmp/trivy.tar.gz" | sha256sum --check
	tar -xzf /tmp/trivy.tar.gz -C /tmp trivy
	sudo mv /tmp/trivy /usr/local/bin/ && rm -f /tmp/trivy.tar.gz

install-gitleaks:
	@echo "=== installing gitleaks $(GITLEAKS_VERSION) (pinned, SHA-256 verified) ==="
	curl -sfL https://github.com/gitleaks/gitleaks/releases/download/v$(GITLEAKS_VERSION)/gitleaks_$(GITLEAKS_VERSION)_linux_x64.tar.gz -o /tmp/gitleaks.tar.gz
	echo "$(GITLEAKS_SHA256)  /tmp/gitleaks.tar.gz" | sha256sum --check
	sudo tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && rm -f /tmp/gitleaks.tar.gz

security-install: install-trivy install-gitleaks
	@echo "Installing security tools (this may require sudo)..."
	sudo apt-get update
	sudo apt-get install -y cppcheck flawfinder
	# Semgrep (pipx isolates it; PyPI download is TLS + hash verified) — CI installs
	# it the same way. cargo-audit resolves through Cargo's checksum-verified index.
	pipx install semgrep || pip install --user semgrep
	cargo install cargo-audit --locked || true
	@echo "Installation finished. Trivy + gitleaks were pinned and SHA-256 verified above."
	@echo "You may need to add ~/.local/bin or /usr/local/bin to your PATH."

semgrep:
	@echo "=== Semgrep (C + Rust + security rules) ==="
	command -v semgrep >/dev/null 2>&1 || pipx install semgrep
	semgrep --version
	semgrep --config=auto --config=p/ci --error .

trivy:
	@echo "=== Trivy (secrets + misconfigs + vulns) ==="
	command -v trivy >/dev/null 2>&1 || $(MAKE) install-trivy
	trivy --version
	trivy fs --scanners vuln,secret,misconfig .

gitleaks:
	@echo "=== gitleaks (secrets in git history) ==="
	command -v gitleaks >/dev/null 2>&1 || $(MAKE) install-gitleaks
	gitleaks detect --source . --verbose   # BLOCKING: non-zero exit on any secret (allowlist in .gitleaks.toml)

cppcheck:
	@echo "=== cppcheck (C static analysis) ==="
	command -v cppcheck >/dev/null 2>&1 || sudo apt-get install -y cppcheck
	cppcheck --version
	cppcheck --enable=all --inconclusive --suppress=missingIncludeSystem src/ include/ rust/ 2>&1 | head -80 || true

flawfinder:
	@echo "=== flawfinder (C/C++ security weaknesses) ==="
	command -v flawfinder >/dev/null 2>&1 || pipx install flawfinder || pip install flawfinder
	flawfinder --version
	flawfinder src/ include/ 2>&1 | head -60 || true

cargo-audit:
	@echo "=== cargo-audit (Rust dependency advisories) ==="
	(cd rust && cargo audit) || echo "cargo-audit not installed or no advisories found"

# ---------------------------------------------------------------------------
# Formal verification: model-check the TLA+ specs in docs/ with TLC.
#
# Both specs carry real, falsifiable safety invariants (cap_algebra: subset-
# rights non-escalation; paging_isolation: per-task frame isolation). TLC
# exits 0 when every reachable state satisfies the invariants and 12 on a
# violation, so this is a hard CI gate. The tla2tools.jar is pinned by version
# and verified by SHA-256 (same discipline as the Trivy/gitleaks downloads);
# it is git-ignored, not committed. Requires a JRE on PATH (CI installs one).
# ---------------------------------------------------------------------------
TLA_TOOLS_VERSION := 1.8.0
TLA_TOOLS_JAR     := tla2tools.jar
# NOTE: this is a mutable GitHub release asset — upstream re-published the v1.8.0
# tla2tools.jar on 2026-07-15 (a rebuilt but functionally identical jar), which
# rotated its hash and broke the old pin (150b0294…). The value below was
# verified against the GitHub release API's authoritative asset digest and by
# inspecting the jar (Implementation-Title "TLA+ Tools", Microsoft vendor,
# tlc2.TLC main class, full tlc2/tla2sany/pcal package set). If CI breaks here
# again with a hash mismatch, re-verify the same way before rotating this pin.
TLA_TOOLS_SHA256  := 58d44845a37a8d776deaf8cf3a623213b59d311bc0ec287bcdfbe148dd11bb3d
TLA_TOOLS_URL     := https://github.com/tlaplus/tlaplus/releases/download/v$(TLA_TOOLS_VERSION)/$(TLA_TOOLS_JAR)

$(TLA_TOOLS_JAR):
	@echo "=== fetching pinned tla2tools $(TLA_TOOLS_VERSION) (SHA-256 verified) ==="
	curl -fsSL -o $@ $(TLA_TOOLS_URL)
	echo "$(TLA_TOOLS_SHA256)  $@" | sha256sum --check

verify-tla: $(TLA_TOOLS_JAR)
	@command -v java >/dev/null 2>&1 || { echo "verify-tla: no 'java' on PATH — install a JRE (CI: default-jre-headless)"; exit 1; }
	@echo "=== TLC: docs/cap_algebra.tla (subset-rights non-escalation) ==="
	cd docs && java -cp ../$(TLA_TOOLS_JAR) tlc2.TLC -config cap_algebra.cfg cap_algebra.tla
	@echo "=== TLC: docs/paging_isolation.tla (per-task frame isolation) ==="
	cd docs && java -cp ../$(TLA_TOOLS_JAR) tlc2.TLC -config paging_isolation.cfg paging_isolation.tla
	@echo "=== TLC: docs/cap_seqlock.tla (two-CPU seqlock: no torn capability read) ==="
	cd docs && java -cp ../$(TLA_TOOLS_JAR) tlc2.TLC -config cap_seqlock.cfg cap_seqlock.tla
	@echo "=== TLC: docs/ipc_toctou.tla (IPC lookup/use: no use-after-revoke) ==="
	cd docs && java -cp ../$(TLA_TOOLS_JAR) tlc2.TLC -config ipc_toctou.cfg ipc_toctou.tla
	@echo "=== TLC: docs/sched_smp.tla (SMP run-pool: no task on two CPUs) ==="
	cd docs && java -cp ../$(TLA_TOOLS_JAR) tlc2.TLC -config sched_smp.cfg sched_smp.tla
	@echo "✅ TLA+ specs model-checked: all invariants hold."

.PHONY: verify-tla
