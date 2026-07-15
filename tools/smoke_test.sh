#!/usr/bin/env bash
#
# Headless QEMU smoke-boot test.
#
# Boots the kernel under QEMU with no display and captures COM1 to a log.
# Success is observing the ring-3 shell's startup banner on the serial line,
# which proves the whole boot path works end to end: kernel init (paging,
# SMEP/SMAP, scheduler), the ELF/flat loader, per-task paging incl. the W^X
# stack, dropping to ring 3 and *executing* there, the syscall dispatch table
# servicing SYS_WRITE, and console output. Any page fault / CPU exception /
# panic on the serial line, or failing to reach the banner before the timeout,
# is a failure.
#
# Usage: tools/smoke_test.sh [boot.iso]
# Env:   SMOKE_TIMEOUT  (seconds, default 40)
#        REQUIRE_MARKER (optional: an extra string that must also appear on
#                        serial for the run to pass — e.g. "ELF_SELFTEST: PASS")
#        FAIL_MARKER    (optional: a string whose appearance is an immediate
#                        failure — e.g. "ELF_SELFTEST: FAIL")
#        MARKER_ONLY    (optional: if "1", REQUIRE_MARKER alone signals success
#                        and the shell banner is NOT required — for self-tests
#                        that intentionally never boot the shell, e.g. the
#                        preemption test whose tasks run forever)
#
set -u

ISO="${1:-boot.iso}"
TIMEOUT="${SMOKE_TIMEOUT:-40}"
REQUIRE_MARKER="${REQUIRE_MARKER:-}"
FAIL_MARKER="${FAIL_MARKER:-}"
MARKER_ONLY="${MARKER_ONLY:-}"

PASS_MARKER="Horus Secure Microkernel"   # printed by userspace/shell.c _start()
LOGIN_MARKER="horus login"               # reached the login prompt (do_login)
FAULT_RE='PAGE FAULT|Exception! Vector|PANIC|Rejected by validator'

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "SMOKE SKIP: qemu-system-x86_64 not found" >&2
    exit 2
fi
if [ ! -f "$ISO" ]; then
    echo "SMOKE FAIL: ISO '$ISO' not found (run 'make boot.iso' first)" >&2
    exit 1
fi

LOG="$(mktemp)"
QEMU_PID=""
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "$QEMU_PID" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$LOG"
}
trap cleanup EXIT

# -accel tcg: GitHub runners have no /dev/kvm; force software emulation so the
#   run is deterministic instead of depending on host virtualization.
# -no-reboot: a triple fault halts QEMU instead of looping, so we detect it.
# isa-debug-exit: present for parity with `make run`; not relied on here.
# Optional persistent ATA disk (SMOKE_DISK=<image>): attaches it as the primary
# IDE drive so a STORAGE_ATA=1 kernel has a real block device to format/mount.
DRIVE_ARG=""
if [ -n "${SMOKE_DISK:-}" ]; then
    # cache=writethrough: every guest write is committed to the host image file
    # immediately, so a two-boot persistence test (QEMU killed after a marker,
    # then re-launched on the same image) never loses the first boot's writes to
    # a writeback cache.
    DRIVE_ARG="-drive file=$SMOKE_DISK,format=raw,if=ide,index=0,cache=writethrough"
fi

# Optional secondary ATA disk (SMOKE_DISK2=<image>): attaches it as IDE index 1,
# i.e. the primary channel's SLAVE device (the boot cdrom already occupies the
# secondary channel). The ring-3 disk_server self-test drives this slave disk; the
# kernel's object store only ever drives the primary master, so the two never
# contend, and IRQ14 is dedicated to the driver.
if [ -n "${SMOKE_DISK2:-}" ]; then
    DRIVE_ARG="$DRIVE_ARG -drive file=$SMOKE_DISK2,format=raw,if=ide,index=1,cache=writethrough"
fi

# SMP_CPUS=<n> boots the guest with n logical CPUs (for the SMP self-test).
SMP_ARG=""
if [ -n "${SMP_CPUS:-}" ]; then
    SMP_ARG="-smp $SMP_CPUS"
fi

qemu-system-x86_64 \
    -m 512M -cpu qemu64,+aes,+rdrand,+smep,+smap -accel tcg \
    -display none -no-reboot -no-shutdown \
    -device isa-debug-exit,iobase=0x604,iosize=0x04 \
    -serial file:"$LOG" -net none \
    $DRIVE_ARG $SMP_ARG \
    -cdrom "$ISO" &
QEMU_PID=$!

status="timeout"
deadline=$(( SECONDS + TIMEOUT ))
while [ "$SECONDS" -lt "$deadline" ]; do
    if grep -qE "$FAULT_RE" "$LOG" 2>/dev/null; then status="fault"; break; fi
    if [ -n "$FAIL_MARKER" ] && grep -qF "$FAIL_MARKER" "$LOG" 2>/dev/null; then status="marker_fail"; break; fi
    # MARKER_ONLY: the required marker alone is success (no shell banner).
    if [ "$MARKER_ONLY" = "1" ] && [ -n "$REQUIRE_MARKER" ]; then
        if grep -qF "$REQUIRE_MARKER" "$LOG" 2>/dev/null; then status="ok"; break; fi
    # Otherwise the banner is the primary success signal; if an extra marker is
    # required, wait until both have appeared.
    elif grep -q "$PASS_MARKER" "$LOG" 2>/dev/null; then
        if [ -z "$REQUIRE_MARKER" ] || grep -qF "$REQUIRE_MARKER" "$LOG" 2>/dev/null; then
            status="ok"; break
        fi
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then status="exited"; break; fi
    sleep 0.5
done

echo "------------------- serial log -------------------"
cat "$LOG" 2>/dev/null || true
echo ""
echo "--------------------------------------------------"

case "$status" in
    ok)
        # A fault (or an explicit fail marker) alongside the banner still fails.
        if grep -qE "$FAULT_RE" "$LOG"; then
            echo "SMOKE FAIL: kernel fault/panic on serial"
            exit 1
        fi
        if [ -n "$FAIL_MARKER" ] && grep -qF "$FAIL_MARKER" "$LOG"; then
            echo "SMOKE FAIL: saw fail marker '$FAIL_MARKER'"
            exit 1
        fi
        if [ "$MARKER_ONLY" = "1" ]; then
            echo "SMOKE PASS: required marker '$REQUIRE_MARKER' observed on serial"
            exit 0
        fi
        extra=""
        [ -n "$REQUIRE_MARKER" ] && extra=" + required marker '$REQUIRE_MARKER'"
        if grep -q "$LOGIN_MARKER" "$LOG"; then
            echo "SMOKE PASS: reached ring-3 shell banner and login prompt$extra"
        else
            echo "SMOKE PASS: reached ring-3 shell banner$extra"
        fi
        exit 0
        ;;
    marker_fail) echo "SMOKE FAIL: saw fail marker '$FAIL_MARKER' on serial"; exit 1 ;;
    fault)   echo "SMOKE FAIL: kernel fault/panic on serial"; exit 1 ;;
    exited)  echo "SMOKE FAIL: QEMU exited before the banner (triple fault?)"; exit 1 ;;
    timeout)
        if [ -n "$REQUIRE_MARKER" ] && ! grep -qF "$REQUIRE_MARKER" "$LOG"; then
            echo "SMOKE FAIL: timed out after ${TIMEOUT}s without required marker '$REQUIRE_MARKER'"
        else
            echo "SMOKE FAIL: timed out after ${TIMEOUT}s before the shell banner"
        fi
        exit 1 ;;
esac
