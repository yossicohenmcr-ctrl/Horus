#include "syscall.h"

/*
 * disk_server -- the first hardware device driver evicted from ring 0.
 *
 * This is a ring-3, capability-confined task that drives an ATA disk with NO
 * kernel privilege: a bug or compromise here faults an unprivileged task that
 * init can restart, instead of corrupting the kernel. It demonstrates the whole
 * ring-3 driver framework end-to-end:
 *
 *   - Port I/O by capability. init delegates two CAP_IO_PORT windows (the ATA
 *     secondary channel: 0x170-0x177 data/command block + 0x376 control). The
 *     kernel opens exactly those ports in this task's TSS I/O-permission bitmap;
 *     every other port (and every task without the cap) faults with #GP. The
 *     `in`/`out` instructions below then run directly in ring 3 -- no syscall.
 *
 *   - Interrupts by capability. init delegates CAP_IRQ(15). This task binds it to
 *     a notification slot with SYS_IRQ_REGISTER; the kernel keeps the PIC/EOI in
 *     ring 0, masks the line on each interrupt, and posts a notification. The
 *     read path below blocks on that notification and SYS_IRQ_ACKs to re-arm the
 *     line -- the driver never touches the interrupt controller.
 *
 * It drives the ATA primary channel's SLAVE device on purpose: the kernel's own
 * encrypted object store only ever drives the primary MASTER (storage.c), so with
 * the driver's disk attached as the slave the two never contend -- yet the IRQ
 * (14) is dedicated to this channel. This proves real ring-3 hardware access
 * against the live controller. The self-test writes a known pattern to a scratch
 * sector via polled PIO, reads it back interrupt-driven, verifies the round-trip,
 * and prints a marker asserted by `make smoke-disk-server`.
 */

/* ATA primary channel (matches the delegated CAP_IO_PORT windows). */
#define ATA_DATA      0x1F0
#define ATA_SECCOUNT  0x1F2
#define ATA_LBA_LOW   0x1F3
#define ATA_LBA_MID   0x1F4
#define ATA_LBA_HIGH  0x1F5
#define ATA_DRIVE     0x1F6
#define ATA_STATUS    0x1F7
#define ATA_COMMAND   0x1F7
#define ATA_CTRL      0x3F6

#define ATA_CMD_READ  0x20
#define ATA_CMD_WRITE 0x30

#define ATA_IRQ       14   /* primary channel */
#define IRQ_NOTIF_SLOT 16  /* free notification slot this driver waits on */
#ifdef STORAGE_RING3_DISK
#define ATA_DRIVE_SEL 0xE0 /* LBA mode, MASTER device: the kernel's real fs disk */
#else
#define ATA_DRIVE_SEL 0xF0 /* LBA mode, SLAVE device (self-test's own scratch disk) */
#endif
#define SCRATCH_LBA   1    /* a sector on the dedicated slave disk image */

/* Direct port I/O -- legal in ring 3 only because our CAP_IO_PORT windows opened
 * these ports in the TSS bitmap. The same instruction on an unheld port #GPs. */
static inline uint8_t inb(uint16_t port) {
    uint8_t v; __asm__ volatile ("inb %1, %0" : "=a"(v) : "d"(port)); return v;
}
static inline void outb(uint16_t port, uint8_t v) {
    __asm__ volatile ("outb %0, %1" : : "a"(v), "d"(port));
}
static inline uint16_t inw(uint16_t port) {
    uint16_t v; __asm__ volatile ("inw %1, %0" : "=a"(v) : "d"(port)); return v;
}
static inline void outw(uint16_t port, uint16_t v) {
    __asm__ volatile ("outw %0, %1" : : "a"(v), "d"(port));
}

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* Bounded BSY poll. A ring-3 spin can never hang the kernel (it is preemptible);
 * a stuck bus just lets the self-test fail on the status/verify check. */
static int wait_not_busy(void) {
    for (uint32_t i = 0; i < 5000000u; i++) {
        if (!(inb(ATA_STATUS) & 0x80)) return 0;   /* BSY clear */
    }
    return -1;
}

static void select_lba(uint32_t lba) {
    outb(ATA_DRIVE,    ATA_DRIVE_SEL | ((lba >> 24) & 0x0F));  /* slave, LBA mode */
    outb(ATA_SECCOUNT, 1);
    outb(ATA_LBA_LOW,  lba & 0xFF);
    outb(ATA_LBA_MID,  (lba >> 8) & 0xFF);
    outb(ATA_LBA_HIGH, (lba >> 16) & 0xFF);
}

/* Polled write of one sector (nIEN=1: no interrupt for the write phase). */
static int write_sector(uint32_t lba, const uint8_t *buf) {
    outb(ATA_CTRL, 0x02);              /* nIEN=1: device IRQ disabled */
    if (wait_not_busy()) return -1;
    select_lba(lba);
    outb(ATA_COMMAND, ATA_CMD_WRITE);
    if (wait_not_busy()) return -1;
    if (inb(ATA_STATUS) & 0x01) return -1;         /* ERR */
    for (int i = 0; i < 256; i++)
        outw(ATA_DATA, (uint16_t)((buf[i*2 + 1] << 8) | buf[i*2 + 0]));
    if (wait_not_busy()) return -1;
    if (inb(ATA_STATUS) & 0x01) return -1;
    return 0;
}

#ifndef STORAGE_RING3_DISK
/* Interrupt-driven read of one sector: enable the device IRQ, issue the command,
 * block on the IRQ notification, drain the data, then ack (re-unmask) the line. */
static int read_sector_irq(uint32_t lba, uint8_t *buf) {
    outb(ATA_CTRL, 0x00);              /* nIEN=0: device raises IRQ on completion */
    if (wait_not_busy()) return -1;
    select_lba(lba);
    outb(ATA_COMMAND, ATA_CMD_READ);

    /* Block until the kernel's IRQ->notification bridge wakes us. The kernel has
     * already EOI'd and masked the line by the time this returns. */
    uint32_t badge = 0;
    if (sys_wait_notify(IRQ_NOTIF_SLOT, &badge) != 0) return -1;

    if (wait_not_busy()) return -1;
    if (inb(ATA_STATUS) & 0x01) return -1;         /* ERR */
    for (int i = 0; i < 256; i++) {
        uint16_t d = inw(ATA_DATA);
        buf[i*2 + 0] = (uint8_t)(d & 0xFF);
        buf[i*2 + 1] = (uint8_t)(d >> 8);
    }
    sys_irq_ack(ATA_IRQ);              /* re-arm the line for the next request */
    return 0;
}

void _start(void) {
    report("disk_server: starting (ring 3, ATA primary channel / slave)\n");

    /* Bind IRQ15 to our notification slot; from here the kernel delivers the
     * secondary-channel interrupt as a notification and unmasks the line. */
    if (sys_irq_register(ATA_IRQ, IRQ_NOTIF_SLOT) != 0) {
        report("DISK_SERVER_SELFTEST: FAIL irq-register\n");
        sys_exit();
    }

    static uint8_t wbuf[512];
    static uint8_t rbuf[512];
    for (int i = 0; i < 512; i++) { wbuf[i] = (uint8_t)(i * 7 + 3); rbuf[i] = 0; }

    if (write_sector(SCRATCH_LBA, wbuf) != 0) {
        report("DISK_SERVER_SELFTEST: FAIL write (no secondary disk?)\n");
        sys_exit();
    }
    if (read_sector_irq(SCRATCH_LBA, rbuf) != 0) {
        report("DISK_SERVER_SELFTEST: FAIL read\n");
        sys_exit();
    }
    for (int i = 0; i < 512; i++) {
        if (rbuf[i] != wbuf[i]) {
            report("DISK_SERVER_SELFTEST: FAIL verify (data mismatch)\n");
            sys_exit();
        }
    }

    report("DISK_SERVER_SELFTEST: PASS ring-3 ATA port-io + IRQ round-trip\n");
    sys_exit();
}
#else  /* STORAGE_RING3_DISK: the block-service role (the real fs disk) */

/* Polled read of one sector (nIEN=1: no interrupts; the kernel's storaged drives
 * us one request at a time, so a simple busy-wait is enough and needs no IRQ cap). */
static int read_sector(uint32_t lba, uint8_t *buf) {
    outb(ATA_CTRL, 0x02);              /* nIEN=1: device IRQ disabled */
    if (wait_not_busy()) return -1;
    select_lba(lba);
    outb(ATA_COMMAND, ATA_CMD_READ);
    if (wait_not_busy()) return -1;
    if (inb(ATA_STATUS) & 0x01) return -1;         /* ERR */
    for (int i = 0; i < 256; i++) {
        uint16_t d = inw(ATA_DATA);
        buf[i*2 + 0] = (uint8_t)(d & 0xFF);
        buf[i*2 + 1] = (uint8_t)(d >> 8);
    }
    return 0;
}

/* Block-service loop. Register as the kernel's block backend, then serve one
 * request at a time: the kernel notifies us with a badge carrying {op, lba}, we
 * PIO 512 bytes to/from our bounce buffer, and signal completion. The kernel only
 * ever hands us CIPHERTEXT (crypto stays in ring 0), and we touch only our granted
 * ATA ports (no DMA), so a fault here is contained to this unprivileged task. */
#define SVC_NOTIF_SLOT 17
static uint8_t g_bounce[512];

void _start(void) {
    report("disk_server: starting (ring 3 block service, ATA primary master)\n");

    /* total_blocks 0 -> the kernel uses its compiled-in volume geometry. */
    if (sys_blkdev_register(g_bounce, SVC_NOTIF_SLOT, 0) != 0) {
        report("disk_server: FAIL blkdev-register\n");
        sys_exit();
    }

    for (;;) {
        uint32_t badge = 0;
        if (sys_wait_notify(SVC_NOTIF_SLOT, &badge) != 0) continue;
        uint32_t lba = badge & 0x7FFFFFFFu;
        int rc = (badge & 0x80000000u) ? write_sector(lba, g_bounce)
                                       : read_sector(lba, g_bounce);
        sys_blkdev_complete(rc);
    }
}
#endif
