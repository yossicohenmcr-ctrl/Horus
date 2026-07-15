#include "syscall.h"

/*
 * Ring-3 init process (PID-1 role).
 *
 * The kernel launches init as the first userspace task and endows it, from the
 * primordial root cnode, with exactly the capabilities it must wield or delegate
 * onward: CAP_AUDIT (slot 7), CAP_CONSOLE (slot 8) and CAP_ENCRYPTED_STORAGE
 * (slot 9); plus a CAP_USER admin cap (slot 6) and two CAP_ENDPOINT caps (slots
 * 10/11) it hands to the servers it launches.
 *
 * init is the delegation root for the system's servers. At boot it:
 *   1. launches the userspace fs_server and provisions it entirely by delegation
 *      (SYS_CAP_GRANT of the IPC gate, listen endpoint, CAP_USER for
 *      registration, and the object-store cap) — no direct kernel cap installs;
 *   2. launches the shell, delegates it CAP_CONSOLE + CAP_ENCRYPTED_STORAGE, and
 *      supervises it with a blocking SYS_WAIT, relaunching it if it exits/faults.
 *
 * Blocking (rather than polling) on the shell means init consumes no CPU while
 * the session runs. init itself never exits.
 *
 * Under INIT_FS_SELFTEST the shell step is replaced by an automated client that
 * drives the delegated server end-to-end (see _start / `make smoke-init-fs`).
 */

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* Preemptible ring-3 spin, used only on the fatal fallback paths below (when
 * there is no shell to wait on). */
static void settle(void) { for (volatile int d = 0; d < 40000; d++) { } }

/* Slots init holds its delegable caps in, matching the kernel endowment in
 * spawn_initial_userspace_init(). */
#define CAP_SLOT_USER       6    /* CAP_USER admin cap (SYS_REGISTER_FS_SERVER gate) */
#define CAP_SLOT_CONSOLE    8    /* CAP_CONSOLE                                      */
#define CAP_SLOT_STORAGE    9    /* CAP_ENCRYPTED_STORAGE (also the object-store cap)*/
#define INIT_EP_GATE_SLOT   10   /* CAP_ENDPOINT, object 0         (coarse IPC gate) */
#define INIT_EP_LISTEN_SLOT 11   /* CAP_ENDPOINT, object FS_EP_REQ (server listen)   */
/* Ring-3 driver framework: the ATA primary-channel device caps init holds to
 * delegate to the disk_server (mirrors the kernel endowment in
 * spawn_initial_userspace_init()). */
#define INIT_IOPORT_CMD_SLOT 12  /* CAP_IO_PORT 0x1F0..0x1F7 */
#define INIT_IOPORT_CTL_SLOT 13  /* CAP_IO_PORT 0x3F6        */
#define INIT_IRQ_SLOT        14  /* CAP_IRQ 14               */
#define INIT_BLKDEV_SLOT     15  /* CAP_BLOCK_DEV            */

/* Launch the userspace fs_server and provision it entirely by delegation: init
 * grants the server all four capabilities it needs — the coarse IPC gate (slot
 * 3), its listen endpoint (slot 4, so SYS_REGISTER_FS_SERVER binds it), the
 * CAP_USER that gates registration (slot 6), and the object-store cap (slot 7) —
 * with no direct kernel cap installs. The grants are authorised because init is
 * uid 0 and holds the server's CAP_TCB from the spawn. Returns the server's task
 * id, or a negative value on a spawn/grant failure. */
static int launch_fs_server(void) {
    int srv = sys_spawn_named("fs_server");
    if (srv <= 0) return -1;
    if (sys_cap_grant(srv, INIT_EP_GATE_SLOT,   3) != 0) return -2;  /* IPC gate            */
    if (sys_cap_grant(srv, INIT_EP_LISTEN_SLOT, 4) != 0) return -3;  /* listen endpoint     */
    if (sys_cap_grant(srv, CAP_SLOT_USER,       6) != 0) return -4;  /* SYS_REGISTER_FS gate */
    if (sys_cap_grant(srv, CAP_SLOT_STORAGE,    7) != 0) return -5;  /* object-store gate   */
    return srv;
}

#if defined(INIT_DISK_SELFTEST) || defined(STORAGE_RING3_DISK)
/* Launch the ring-3 disk_server and provision it purely by delegation: an
 * endpoint cap (slot 3) so it can block on the IRQ notification, plus the ATA
 * primary-channel device caps -- two CAP_IO_PORT windows, CAP_IRQ 14, and the
 * CAP_BLOCK_DEV registration gate. init holds the driver's CAP_TCB from the
 * spawn, so the grants are authorised. Returns the task id, or negative on
 * failure. */
static int launch_disk_server(void) {
    int srv = sys_spawn_named("disk_server");
    if (srv <= 0) return -1;
    if (sys_cap_grant(srv, INIT_EP_GATE_SLOT,    3)  != 0) return -2;  /* notif gate     */
    if (sys_cap_grant(srv, INIT_IOPORT_CMD_SLOT, 12) != 0) return -3;  /* 0x1F0..0x1F7   */
    if (sys_cap_grant(srv, INIT_IOPORT_CTL_SLOT, 13) != 0) return -4;  /* 0x3F6          */
    if (sys_cap_grant(srv, INIT_IRQ_SLOT,        14) != 0) return -5;  /* IRQ 14         */
    if (sys_cap_grant(srv, INIT_BLKDEV_SLOT,     15) != 0) return -6;  /* block-dev gate */
    return srv;
}
#endif

/* Spawn the shell and delegate it the console + storage capabilities. Returns
 * the shell's task id, or a negative value on failure. */
static int launch_shell(void) {
    int sh = sys_spawn_named("shell");
    if (sh <= 0) return -1;
    /* Delegate least privilege into the same slots the shell expects (8/9).
     * Done immediately after the spawn, before the shell needs them for login;
     * init holds a CAP_TCB to the shell from the spawn, so the grants pass. */
    if (sys_cap_grant(sh, CAP_SLOT_CONSOLE, CAP_SLOT_CONSOLE) != 0) return -2;
    if (sys_cap_grant(sh, CAP_SLOT_STORAGE, CAP_SLOT_STORAGE) != 0) return -3;
    return sh;
}

void _start(void) {
#ifdef STORAGE_RING3_DISK
    /* Ring-3 block driver: bring the disk_server up FIRST so it registers as the
     * kernel's block backend (and triggers the deferred mount) before fs_server
     * needs the store. Long-lived server — provision and leave it running. */
    int ds = launch_disk_server();
    if (ds < 0) report("init: WARNING disk_server provisioning failed\n");
    else        report("init: ring-3 disk_server launched and provisioned\n");
#endif

    /* Bring up the filesystem server first, so it is registered and serving by
     * the time the shell (or the test client) issues its first request. */
    int srv = launch_fs_server();
    if (srv < 0) report("init: WARNING fs_server provisioning failed\n");
    else         report("init: fs_server launched and provisioned\n");

#ifdef INIT_DISK_SELFTEST
    /* Ring-3 driver proof: launch the disk_server by delegation alone and let it
     * drive the ATA secondary channel from ring 3. Its DISK_SERVER_SELFTEST marker
     * (asserted by `make smoke-disk-server`) is the proof; block until it finishes
     * so the marker is flushed before anything else runs. */
    report("INIT_DISK_SELFTEST: launching ring-3 disk_server by delegation\n");
    int ds = launch_disk_server();
    if (ds < 0) { report("DISK_SERVER_SELFTEST: FAIL provision\n"); for (;;) settle(); }
    sys_wait(ds);
    report("INIT_DISK_SELFTEST: disk_server exited\n");
    for (;;) settle();
#endif

#ifdef INIT_FS_SELFTEST
    /* Boot-time FS integration test: prove init brings up fs_server by delegation
     * alone and the delegated server serves a client end-to-end. The client's own
     * FS_SELFTEST: PASS marker (asserted by `make smoke-init-fs`) is the proof. */
    report("INIT_FS_SELFTEST: init launched fs_server by delegation; driving client\n");
    int cli = sys_spawn_named("fsclient");
    if (cli <= 0) { report("INIT_FS_SELFTEST: FAIL spawn-client\n"); for (;;) settle(); }
    if (sys_cap_grant(cli, INIT_EP_GATE_SLOT, 3) != 0) {
        report("INIT_FS_SELFTEST: FAIL grant-client\n"); for (;;) settle();
    }
    sys_wait(cli);   /* block until the client finishes driving the server */
    report("INIT_FS_SELFTEST: init supervised fs client to exit\n");
    for (;;) settle();
#else
    report("init: starting, launching shell\n");

    /* Launch the shell, then block in SYS_WAIT until it exits or faults, and
     * relaunch. SYS_WAIT suspends init on the preemptive block/switch path, so
     * while the shell runs init is off the run queue entirely (no polling). The
     * fs_server launched above keeps serving alongside the shell. */
    for (;;) {
        int sh = launch_shell();
        if (sh < 0) { report("init: FATAL could not launch shell\n"); for (;;) settle(); }

        sys_wait(sh);   /* returns once the shell task is dead */
        report("init: shell exited, relaunching\n");
    }
#endif
}
