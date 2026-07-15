/* kshell.c -- in-kernel debug shell command processor + boot userspace
 * launchers. The DEBUG_SHELL command loop, its help/history/console-cap
 * helpers, and spawn_initial_userspace_{init,shell}() live here. Split out of
 * syscall.c. */
#include "syscall_internal.h"

#ifdef DEBUG_SHELL
static void help_line(const char *name, const char *desc) {
    print("  ");
    print(name);
    int len = 0; while (name[len]) len++;
    for (int i = len; i < 22; i++) print(" ");
    print("- ");
    println(desc);
}

/* Accurate list of what the in-kernel debug shell actually dispatches (see the
 * action handlers in process_user_command). Kept in sync with that switch; the
 * old one-liner advertised `fs`/`spawn` (never handled here) and omitted half
 * the real commands. "(cap)" marks ops gated on a capability. */
static void show_general_help(void) {
    set_text_colour(0x0B);
    println("Horus kernel debug shell - commands");
    set_text_colour(0x0F);
    println("Info:");
    help_line("help [cmd], man, ?",  "This list, or details for one command");
    help_line("version",            "Kernel version banner");
    help_line("uptime",             "System uptime in timer ticks");
    help_line("ps",                 "List tasks (full view needs CAP_CONSOLE)");
    help_line("caps",               "List this task's capability slots");
    help_line("dmesg, log",         "Dump the kernel log (cap: CAP_CONSOLE)");
    println("Session:");
    help_line("echo <text>",        "Print text back");
    help_line("clear",              "Clear the screen (cap: slot-3 WRITE)");
    help_line("yield",              "Yield the CPU to the scheduler");
    help_line("exit",               "Power off the machine (cap: CAP_CONSOLE)");
    println("Capabilities & tasks:");
    help_line("mint <d> <s> <r>",   "Mint cap: dest<-src slot with rights mask r");
    help_line("kill <pid>",         "Terminate a task (cap: CAP_CONSOLE)");
    help_line("load",               "Receive a binary on :4444 then spawn it");
    println("Storage:");
    help_line("rotate_keys",        "Re-encrypt your blocks (cap: CONSOLE+ENC_STORAGE)");
    set_text_colour(0x08);
    println("Numbers are decimal. 'rights' is a decimal bitmask (see ARCHITECTURE.md).");
    set_text_colour(0x0F);
}
#endif

#ifdef DEBUG_SHELL
static void show_topic_help(const char *topic) {
    while (*topic == ' ') topic++;
    if (kstrcmp(topic, "mint") == 0) {
        println("mint <dest> <src> <rights>");
        println("  Derive a new capability into slot <dest> from the cap in slot");
        println("  <src>, keeping at most <rights> (a decimal bitmask). The source");
        println("  must carry CAP_RIGHT_MINT; dest must be >= 4 (slots 0-3 reserved).");
        return;
    }
    if (kstrcmp(topic, "kill") == 0) {
        println("kill <pid>");
        println("  Terminate task <pid>. Requires CAP_CONSOLE (slot 8). You cannot");
        println("  kill pid 0 (the kernel/init task).");
        return;
    }
    if (kstrcmp(topic, "load") == 0) {
        println("load");
        println("  Wait on serial port 4444 for a headered program image, then spawn");
        println("  it as a new ring-3 task. Requires a FRAME cap (slot 3, WRITE|EXEC)");
        println("  and CAP_CONSOLE. Pipe a .bin built by tools/mkheadered to :4444.");
        return;
    }
    if (kstrcmp(topic, "rotate_keys") == 0) {
        println("rotate_keys");
        println("  Re-encrypt the storage blocks you own under a freshly derived key");
        println("  (ChaCha20+HMAC AEAD). Requires CAP_CONSOLE and CAP_ENCRYPTED_STORAGE.");
        return;
    }
    println("No per-topic help for that command. Showing the full list:");
    show_general_help();
}
#endif

#ifdef DEBUG_SHELL
static bool has_console_cap(void) {
    struct capability *c = cap_lookup(8, 0);
    return (c && c->type == CAP_CONSOLE);
}
#endif

extern tcb_t tasks[MAX_TASKS];

#ifdef DEBUG_SHELL
char cmd_history[HISTORY_SIZE][CMD_MAX];
int history_count = 0;
int history_pos = -1;
#endif

#ifdef DEBUG_SHELL
static void qemu_exit(int code) {
    outb(0x604, (uint8_t)code);
    outb(0x604, 0x00);
    asm volatile("lidt 0x0");
    asm volatile("int $0x0");
    for (;;) {
        asm volatile("cli; hlt");
    }
}
#endif

#ifdef DEBUG_SHELL
int process_user_command(const char *cmd) {
    while (*cmd == ' ') cmd++;

    if (cmd[0] == 0 || cmd[0] == '\n' || cmd[0] == '\r') {
        return 0;
    }

    
    if (kstrcmp(cmd, "help") == 0 || kstrcmp(cmd, "man") == 0 || cmd[0] == '?') {
        show_general_help();
        return 0;
    }
    if (kstrncmp(cmd, "help ", 5) == 0 || kstrncmp(cmd, "man ", 4) == 0 ||
        (cmd[0] == '?' && (cmd[1] == ' ' || cmd[1] == 0))) {
        const char *topic = cmd;
        if (cmd[0] == 'h') topic += 5;
        else if (cmd[0] == 'm') topic += 4;
        else topic += 1; 
        show_topic_help(topic);
        return 0;
    }

    int action = rust_handle_command((const uint8_t *)cmd, kstrlen(cmd));
    if (action == 43) {
        set_text_colour(0x0A);
        println("Horus v0.4 - x86 microkernel (per-task isolation + Rust policy)");
        set_text_colour(0x0F);
        return 0;
    }
    if (action == 45) {
        uint32_t ticks = get_system_ticks();
        print("Uptime: "); print_hex(ticks); println(" ticks");
        return 0;
    }
    if (action == 46) {
        
        bool can_see_all = has_console_cap();
        set_text_colour(0x0B);
        println("PID  UID    NAME            STATE  HEAP      CAPS  FLAGS");
        set_text_colour(0x0F);
        int cur = get_current_task();
        for (int i = 0; i < MAX_TASKS; i++) {
            if (tasks[i].state != 0) {
                if (!can_see_all && i != cur) continue;
                if (i < 10) print(" ");
                print_decimal(i);
                print("   ");
                /* UID, right-padded to a 7-col field (0 shown as root). */
                if (tasks[i].uid == 0) { print("root  "); }
                else { print_decimal(tasks[i].uid); for (int sp = (tasks[i].uid < 10 ? 1 : (tasks[i].uid < 100 ? 2 : (tasks[i].uid < 1000 ? 3 : 4))); sp < 6; sp++) print(" "); }
                print(" ");
                print(tasks[i].name);
                int nlen = 0; while (tasks[i].name[nlen]) nlen++;
                for (int sp = nlen; sp < 16; sp++) print(" ");
                /* Named state from the Rust ps policy (run/blkd/dead/?). */
                const char *sn = rust_task_state_name(tasks[i].state);
                print(sn);
                for (int sp = 0; sn[sp]; sp++) { /* pad name col */ }
                int snlen = 0; while (sn[snlen]) snlen++;
                for (int sp = snlen; sp < 7; sp++) print(" ");
                print_decimal(tasks[i].heap_current - tasks[i].heap_start);
                print("      ");
                print_decimal(tasks[i].caps_in_use);
                print("    ");
                if (tasks[i].in_kernel) print("K ");
                if (tasks[i].blocked_on >= 0) { print("B"); print_decimal(tasks[i].blocked_on); }
                else if (tasks[i].blocked_on_notif >= 0) print("N");
                println("");
            }
        }
        if (!can_see_all) {
            set_text_colour(0x0E);
            println("(Limited view: CAP_CONSOLE required for full system ps)");
            set_text_colour(0x0F);
        }
        return 0;
    }
    if (action == 47) {
        struct capability *cspace = tasks[get_current_task()].cspace;
        uint32_t size = tasks[get_current_task()].cspace_size ? tasks[get_current_task()].cspace_size : 256;

        print("Caps for task "); print_hex(get_current_task()); println(":");

        for (uint32_t i = 0; i < size && i < 16; i++) {
            struct capability *c = &cspace[i];
            if (c->type != CAP_NULL) {
                print("  ["); print_hex(i);
                print("] type="); print_hex(c->type);
                print(" rights="); print_hex(c->rights);
                print(" obj="); print_hex(c->object);
                println("");
            }
        }
        return 0;
    }
    if (action == 48) {
        struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE);
        if (!c) return -1;
        clear_screen();
        return 0;
    }
    if (action == 49) {
        
        if (!has_console_cap()) {
            println("Permission denied (CAP_CONSOLE required in slot 8)");
            return -1;
        }
        uint32_t id = 0;
        const char *p = cmd + 5;
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { id = id * 10 + (*p - '0'); p++; }

        if (id == 0 || id >= MAX_TASKS) {
            println("Invalid task id");
            return -1;
        }
        if (tasks[id].state == 0) {
            println("Task already dead");
            return 0;
        }
        if (tasks[id].waiter >= 0) {
            int w = tasks[id].waiter;
            if (w < MAX_TASKS && tasks[w].state == TASK_BLOCKED_WAIT) {
                tasks[w].state        = TASK_RUNNABLE;
                tasks[w].runnable_ctx = 1;
            }
            tasks[id].waiter = -1;
        }

        tasks[id].state = 0;
        print("Killed "); print_hex(id); println("");
        if ((int)id == get_current_task()) kernel_idle();
        return 0;
    }
    if (action == 1) {
        
        if (!has_console_cap()) {
            println("Permission denied (CAP_CONSOLE required for exit)");
            return -1;
        }
        println("Exiting...");
        qemu_exit(0);
        return 0;
    }

    if (action == 44) {
        const char *arg = cmd + 5;
        while (*arg == ' ') arg++;
        print(arg);
        println("");
        return 0;
    }
    if (action == 50) {
        uint32_t dest = 0, src = 0, rights = 0;
        const char *p = cmd + 5;
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { dest = dest * 10 + (*p - '0'); p++; }
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { src = src * 10 + (*p - '0'); p++; }
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { rights = rights * 10 + (*p - '0'); p++; }

        if (cap_mint(dest, src, rights)) {
            println("mint ok");
            return 0;
        } else {
            println("mint failed");
            return -1;
        }
    }

    if (action == 36) {
        
        if (!has_console_cap()) {
            println("Permission denied (CAP_CONSOLE required for rotate_keys)");
            return -1;
        }
        if (get_current_task() != 0 && !has_encrypted_storage_cap()) {
            println("Permission denied (CAP_ENCRYPTED_STORAGE required for rotate_keys)");
            return -1;
        }
        int n = do_rotate_keys();
        print("Rotated "); print_decimal((uint32_t)n); println(" blocks");
        return 0;
    }

    if (cmd[0] == 'y' && cmd[1] == 'i' && cmd[2] == 'e' && cmd[3] == 'l' && cmd[4] == 'd' &&
        (cmd[5] == 0 || cmd[5] == ' ')) {
        /* In-kernel debug shell has no live user trap frame; yield is a no-op. */
        return 0;
    }

    if (kstrcmp(cmd, "dmesg") == 0 || kstrcmp(cmd, "log") == 0) {
        
        if (!has_console_cap()) {
            println("Permission denied (CAP_CONSOLE required for dmesg)");
            return -1;
        }
        dump_kernel_log();
        return 0;
    }

    if (cmd[0] == 'l' && cmd[1] == 'o' && cmd[2] == 'a' && cmd[3] == 'd' && cmd[4] == 0) {
        struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC);
        if (!c) {
            println("Permission denied (need FRAME cap slot 3)");
            return -1;
        }
        if (!has_console_cap()) {
            println("Permission denied (CAP_CONSOLE also required to load/spawn)");
            return -1;
        }

        println("");
        println("QEMU VGA window shows output (close it with WM X; does not kill your shell tab).");
        println("Kernel shell is on 4445 (use this or another terminal): nc localhost 4445");
        println("Loader (for the program image) is on 4444 (second terminal):");
        println("  From Horus root: cat userspace/shell.bin | nc localhost 4444");
        println("  Inside userspace/: cat shell.bin | nc localhost 4444");
        println("Waiting on 4444 for the binary...");
        struct program_header h;
        int r = do_receive_program(&h);
        if (r != 0) {
            println("Receive failed or bad header");
            return -1;
        }
        print("Received '"); print(h.name); print("' ");
        print_decimal(h.size); println(" bytes - spawning...");
        int pid = do_spawn();
        if (pid > 0) {
            /* Drop into the new task via the full-context path (fabricated frame
             * from do_spawn). Does not return. */
            sched_enable_preemption();
            sched_enter_user(pid);
        } else {
            println("Spawn failed after receive");
            return -1;
        }
    }

    println("Unknown command. Type 'help' or 'help <cmd>' for usage.");
    return -1;
}
#endif

/* Launch the ring-3 init process (PID-1 role) as the first userspace task,
 * replacing the former "kernel spawns the shell directly" arrangement. init is
 * endowed with exactly the capabilities it needs to do its job and no more:
 * CAP_AUDIT (slot 7) to observe its children's liveness, and CAP_CONSOLE (slot 8)
 * + CAP_ENCRYPTED_STORAGE (slot 9) to delegate to the shell it spawns. init then
 * launches and supervises the shell from ring 3 (see userspace/init.c), handing
 * it those two caps via SYS_CAP_GRANT. Structure mirrors the old shell launcher:
 * stage the embedded image, do_spawn, endow, then sched_enter_user into ring 3. */
void spawn_initial_userspace_init(void) {
    extern uint8_t embedded_init_bin_start[];
    extern uint8_t embedded_init_bin_end[];
    extern int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
    uint32_t full_sz = (uint32_t)(embedded_init_bin_end - embedded_init_bin_start);
    if (full_sz < 44) return;
    const uint8_t *bin = embedded_init_bin_start;
    uint32_t magic = *(const uint32_t *)bin;
    uint32_t h_entry = *(const uint32_t *)(bin + 4);
    uint32_t h_size = *(const uint32_t *)(bin + 8);
    if (magic != 0x55524F48) return;
    if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) return;
    if (full_sz < 44 + h_size) h_size = full_sz - 44;
    armed_hdr.entry = h_entry;
    armed_hdr.size = h_size;
    const uint8_t *payload = bin + 44;
    for (uint32_t i = 0; i < h_size; i++) loader_staging[i] = payload[i];
    program_armed = 1;
    int pid = do_spawn();
    if (pid > 0) {
        tasks[pid].uid = 0;   /* init is the privileged supervisor */
        /* Least privilege: only what init must wield (audit) or delegate onward.
         * Copied from the primordial root cnode with fresh serials so init's —
         * and its grantees' — cap_lookups accept them. */
        cap_install_from_root(pid, 7, 7, 0);   /* root[7] = CAP_AUDIT             */
        cap_install_from_root(pid, 8, 8, 0);   /* root[8] = CAP_CONSOLE           */
        cap_install_from_root(pid, 9, 9, 0);   /* root[9] = CAP_ENCRYPTED_STORAGE */
        /* init is the delegation root for the userspace servers it launches: it
         * holds a CAP_USER admin cap (slot 6, the SYS_REGISTER_FS_SERVER gate) and
         * two CAP_ENDPOINT caps for a server's coarse IPC gate (slot 3) and its
         * listen endpoint (slot 4, object FS_EP_REQ=4). The object-store authority
         * it delegates for the server's slot 7 comes from the CAP_ENCRYPTED_STORAGE
         * cap already at slot 9. It hands these to fs_server with SYS_CAP_GRANT —
         * see launch_fs_server() in userspace/init.c. Slots 10-11 are free slots
         * init delegates from. */
        cap_install_from_root(pid, 6, 6, 0);    /* root[6] = CAP_USER (ALL)                 */
        cap_install_from_root(pid, 10, 2, 0);   /* root[2] = CAP_ENDPOINT, object 0 (gate)  */
        cap_install_from_root(pid, 11, 2, 4);   /* root[2] = CAP_ENDPOINT, object FS_EP_REQ */
        /* Ring-3 driver framework: the ATA primary-channel device caps, so init
         * can delegate them to the disk_server it launches (see launch_disk_server
         * in userspace/init.c). Two CAP_IO_PORT windows + CAP_IRQ 14 + the
         * CAP_BLOCK_DEV registration gate. init is the trusted delegation root; as
         * with CAP_ENCRYPTED_STORAGE it holds these only to hand them down. */
        /* The 4th arg is the cap's object and OVERRIDES the root cap's, so pass the
         * exact encodings the disk_server expects (window (base<<16)|count, IRQ
         * line, 0). Passing 0 here would hand init a zero-width port window and a
         * CAP_IRQ naming line 0 -- the driver's port/IRQ claims would then fail. */
        cap_install_from_root(pid, 12, 12, ((uint32_t)0x1F0 << 16) | 8);  /* CAP_IO_PORT 0x1F0..0x1F7 */
        cap_install_from_root(pid, 13, 13, ((uint32_t)0x3F6 << 16) | 1);  /* CAP_IO_PORT 0x3F6        */
        cap_install_from_root(pid, 14, 14, 14);                          /* CAP_IRQ line 14          */
        cap_install_from_root(pid, 15, 15, 0);                           /* CAP_BLOCK_DEV            */

        /* do_spawn already fabricated a full trap frame; enter via the same
         * pop+iretq path every later resume uses. */
        sched_enable_preemption();
        sched_enter_user(pid);
    }
}

void spawn_initial_userspace_shell(void) {
    extern uint8_t embedded_shell_bin_start[];
    extern uint8_t embedded_shell_bin_end[];
    uint32_t full_sz = (uint32_t)(embedded_shell_bin_end - embedded_shell_bin_start);
    if (full_sz < 44) return;
    const uint8_t *bin = embedded_shell_bin_start;
    uint32_t magic = *(const uint32_t *)bin;
    uint32_t h_entry = *(const uint32_t *)(bin + 4);
    uint32_t h_size = *(const uint32_t *)(bin + 8);
    if (magic != 0x55524F48) return;
    if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) return;
    if (full_sz < 44 + h_size) h_size = full_sz - 44;
    armed_hdr.entry = h_entry;
    armed_hdr.size = h_size;
    const uint8_t *payload = bin + 44;
    for (uint32_t i = 0; i < h_size; i++) {
        loader_staging[i] = payload[i];
    }
    program_armed = 1;
    int pid = do_spawn();
    if (pid > 0) {
        uint32_t s8 = 0;
        uint32_t s9 = 0;
        if (tasks[0].cspace[8].type != CAP_NULL) s8 = cap_alloc_fresh_serial();
        if (tasks[0].cspace[9].type != CAP_NULL) s9 = cap_alloc_fresh_serial();
        spin_lock(&cap_lock);
        if (tasks[0].cspace && tasks[pid].cspace) {
            if (tasks[0].cspace[8].type != CAP_NULL) {
                tasks[pid].cspace[8] = tasks[0].cspace[8];
                tasks[pid].cspace[8].serial = s8;
            }
            if (tasks[0].cspace[9].type != CAP_NULL) {
                tasks[pid].cspace[9] = tasks[0].cspace[9];
                tasks[pid].cspace[9].serial = s9;
            }
        }
        spin_unlock(&cap_lock);


        /* Boot's delicate single-threaded init is done; arm the timer and
         * enter via the fabricated full trap frame (do_spawn). */
        sched_enable_preemption();
        sched_enter_user(pid);
    }
}

