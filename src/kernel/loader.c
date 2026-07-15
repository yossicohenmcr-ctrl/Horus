/* loader.c -- program image loading: named embedded binaries, the serial
 * receive path, the i386 ELF loader (try_elf_load + relocations + W^X), and
 * image placement/copy into a task. Owns the shared loader staging state
 * (declared extern in syscall_internal.h). Split out of syscall.c. */
#include "syscall_internal.h"

uint8_t loader_staging[MAX_PROGRAM_SIZE];
struct program_header armed_hdr;
int program_armed = 0;

/* Named embedded binaries — always available for spawn-by-name.
 * Each .bin file has a 44-byte Horus header: magic(4), entry(4), size(4),
 * name[32], followed by the ELF/flat payload. */
struct embedded_binary {
    const char *name;
    const uint8_t *start;
    const uint8_t *end;
};

extern uint8_t embedded_shell_bin_start[];
extern uint8_t embedded_shell_bin_end[];
extern uint8_t embedded_hello_bin_start[];
extern uint8_t embedded_hello_bin_end[];
extern uint8_t embedded_captest_bin_start[];
extern uint8_t embedded_captest_bin_end[];
extern uint8_t embedded_fsserver_bin_start[];
extern uint8_t embedded_fsserver_bin_end[];
#ifdef INIT_FS_SELFTEST
extern uint8_t embedded_fsclient_bin_start[];
extern uint8_t embedded_fsclient_bin_end[];
#endif
#if defined(INIT_DISK_SELFTEST) || defined(STORAGE_RING3_DISK)
extern uint8_t embedded_diskserver_bin_start[];
extern uint8_t embedded_diskserver_bin_end[];
#endif
#ifdef PROC_SELFTEST
extern uint8_t embedded_exectest_bin_start[];
extern uint8_t embedded_exectest_bin_end[];
extern uint8_t embedded_grantee_bin_start[];
extern uint8_t embedded_grantee_bin_end[];
extern uint8_t embedded_sigtarget_bin_start[];
extern uint8_t embedded_sigtarget_bin_end[];
extern uint8_t embedded_faulter_bin_start[];
extern uint8_t embedded_faulter_bin_end[];
extern uint8_t embedded_sigwaiter_bin_start[];
extern uint8_t embedded_sigwaiter_bin_end[];
extern uint8_t embedded_argtest_bin_start[];
extern uint8_t embedded_argtest_bin_end[];
#endif

static const struct embedded_binary embedded_binaries[] = {
    { "shell",     embedded_shell_bin_start,   embedded_shell_bin_end   },
    { "hello",     embedded_hello_bin_start,   embedded_hello_bin_end   },
    { "captest",   embedded_captest_bin_start, embedded_captest_bin_end },
    { "fs_server", embedded_fsserver_bin_start,embedded_fsserver_bin_end},
#ifdef INIT_FS_SELFTEST
    /* fsclient: spawned by name from init to drive the delegated fs_server over
     * IPC. INIT_FS_SELFTEST only. */
    { "fsclient",  embedded_fsclient_bin_start, embedded_fsclient_bin_end },
#endif
#if defined(INIT_DISK_SELFTEST) || defined(STORAGE_RING3_DISK)
    /* disk_server: spawned by name from init — the ring-3 ATA driver (self-test
     * proof, or the STORAGE_RING3_DISK block-service backend). */
    { "disk_server", embedded_diskserver_bin_start, embedded_diskserver_bin_end },
#endif
#ifdef PROC_SELFTEST
    /* exectest: spawnable by name so the proc self-test can launch a child that
     * exercises SYS_EXEC_NAMED (it execs into "hello"). PROC_SELFTEST only. */
    { "exectest",  embedded_exectest_bin_start, embedded_exectest_bin_end },
    /* grantee: child that exercises SYS_CAP_GRANT (uses a delegated CAP_AUDIT and
     * checks fail-closed upward). PROC_SELFTEST only. */
    { "grantee",   embedded_grantee_bin_start,  embedded_grantee_bin_end  },
    /* sigtarget: child that registers a handler and is signalled by the driver to
     * exercise SYS_SIGNAL (async task-to-task delivery). PROC_SELFTEST only. */
    { "sigtarget", embedded_sigtarget_bin_start, embedded_sigtarget_bin_end},
    /* faulter: child that takes an unhandled #UD fault, so the driver can verify
     * a SYS_WAIT waiter is woken on a *fault* death too. PROC_SELFTEST only. */
    { "faulter",   embedded_faulter_bin_start,  embedded_faulter_bin_end  },
    /* sigwaiter: blocks in SYS_WAIT on an immortal target so the driver can
     * verify a signal interrupts the blocked wait. PROC_SELFTEST only. */
    { "sigwaiter", embedded_sigwaiter_bin_start, embedded_sigwaiter_bin_end},
    /* argtest: spawned with an argv to verify full argument passing. PROC_SELFTEST only. */
    { "argtest",   embedded_argtest_bin_start,  embedded_argtest_bin_end  },
#endif
    { NULL, NULL, NULL }
};

/* Arm the staging buffer from a named embedded binary.
 * Returns 0 on success, negative on error (not found, bad magic, too large). */
int arm_named_binary(const char *name) {
    for (int i = 0; embedded_binaries[i].name != NULL; i++) {
        if (kstrcmp(embedded_binaries[i].name, name) != 0) continue;
        const uint8_t *bin = embedded_binaries[i].start;
        uint32_t full_sz = (uint32_t)(embedded_binaries[i].end - bin);
        if (full_sz < 44) return -1;
        uint32_t magic   = (uint32_t)bin[0] | ((uint32_t)bin[1]<<8) |
                           ((uint32_t)bin[2]<<16) | ((uint32_t)bin[3]<<24);
        uint32_t h_entry = (uint32_t)bin[4] | ((uint32_t)bin[5]<<8) |
                           ((uint32_t)bin[6]<<16) | ((uint32_t)bin[7]<<24);
        uint32_t h_size  = (uint32_t)bin[8] | ((uint32_t)bin[9]<<8) |
                           ((uint32_t)bin[10]<<16) | ((uint32_t)bin[11]<<24);
        if (magic != 0x55524F48u) return -2;
        if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) return -3;
        if (full_sz < 44 + h_size) h_size = full_sz - 44;
        for (uint32_t j = 0; j < h_size; j++) loader_staging[j] = bin[44 + j];
        armed_hdr.entry = h_entry;
        armed_hdr.size  = h_size;
        for (int k = 0; k < 31; k++) armed_hdr.name[k] = (char)bin[12 + k];
        armed_hdr.name[31] = 0;
        program_armed = 1;
        return 0;
    }
    return -4;  /* not found */
}

/* Arm the staging buffer from a program image the caller supplies in its own
 * address space (execve-from-fd): the caller reads the image from a file — via
 * the userspace fs_server over IPC, the normal filesystem read path — into a
 * buffer and hands (ubuf, len) here. This is the same trust model as
 * SYS_RECEIVE_PROGRAM (which stages an image received over serial): the bytes
 * are untrusted and are validated by the same loader (try_elf_load: W^X, bounds,
 * fail-closed relocations) before anything runs. Two container formats are
 * accepted, mirroring arm_named_binary:
 *   - a 44-byte Horus header {magic,entry,size,name[32]} + payload (a `.bin`), or
 *   - a bare ELF (0x7f 'E' 'L' 'F'), whose entry the ELF loader computes.
 * Every read is bounds-checked and goes through copy_from_user (present/user
 * checks, SMAP-safe) against the *current* task, so it must run while the
 * caller's address space is still active. Fails closed (program_armed left 0,
 * negative return) on a bad pointer, an over-long/short image, or an
 * unrecognised container. `name_hint` (may be NULL) names a bare-ELF image and
 * backfills an empty Horus name. Returns 0 on success, negative on error. */
int arm_image_from_user(uint32_t ubuf, uint32_t len, const char *name_hint) {
    program_armed = 0;
    if (ubuf == 0)                             return -1;
    if (len < 4 || len > MAX_PROGRAM_SIZE)     return -2;

    uint8_t probe[4];
    if (copy_from_user(probe, (const void *)(addr_t)ubuf, 4) != 0) return -3;
    uint32_t m = (uint32_t)probe[0] | ((uint32_t)probe[1] << 8) |
                 ((uint32_t)probe[2] << 16) | ((uint32_t)probe[3] << 24);

    uint32_t payload_off, payload_len, h_entry;
    char hname[32];
    hname[0] = 0;

    if (len >= 44 && m == 0x55524F48u) {            /* Horus .bin: header + payload */
        uint8_t hdr[44];
        if (copy_from_user(hdr, (const void *)(addr_t)ubuf, 44) != 0) return -3;
        h_entry = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8) |
                  ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
        uint32_t h_size = (uint32_t)hdr[8] | ((uint32_t)hdr[9] << 8) |
                          ((uint32_t)hdr[10] << 16) | ((uint32_t)hdr[11] << 24);
        if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) return -4;
        if (44u + h_size > len) h_size = len - 44u;  /* clamp to what was supplied */
        payload_off = 44;
        payload_len = h_size;
        for (int k = 0; k < 31; k++) hname[k] = (char)hdr[12 + k];
        hname[31] = 0;
    } else if (probe[0] == 0x7f && probe[1] == 'E' &&
               probe[2] == 'L' && probe[3] == 'F') {  /* bare ELF */
        h_entry = 0;                                 /* try_elf_load computes it */
        payload_off = 0;
        payload_len = len;
    } else {
        return -5;                                   /* unrecognised container: fail closed */
    }

    for (uint32_t off = 0; off < payload_len; ) {
        uint32_t chunk = payload_len - off;
        if (chunk > USER_MEM_MAX_COPY) chunk = USER_MEM_MAX_COPY;
        if (copy_from_user(loader_staging + off,
                           (const void *)((addr_t)ubuf + payload_off + off), chunk) != 0)
            return -6;
        off += chunk;
    }

    if (hname[0] == 0 && name_hint) {
        int k = 0;
        for (; k < 31 && name_hint[k]; k++) hname[k] = name_hint[k];
        hname[k] = 0;
    }

    armed_hdr.entry = h_entry;
    armed_hdr.size  = payload_len;
    for (int k = 0; k < 32; k++) armed_hdr.name[k] = hname[k];
    armed_hdr.name[31] = 0;
    program_armed = 1;
    return 0;
}


static int loader_receive_to_staging(struct program_header *out_hdr) {
    struct program_header hdr;
    uint8_t *p = (uint8_t *)&hdr;

    p[0] = serial2_read_char();
    for (size_t i = 1; i < sizeof(hdr); i++) {
        p[i] = serial2_read_char();
    }

    if (hdr.magic != 0x55524F48) {
        return -1;
    }
    if (hdr.size == 0 || hdr.size > MAX_PROGRAM_SIZE) {
        return -2;
    }

    for (uint32_t i = 0; i < hdr.size; i++) {
        loader_staging[i] = serial2_read_char();
    }

    armed_hdr = hdr;
    program_armed = 1;

    if (out_hdr) {
        *out_hdr = hdr;
    }
    return 0;
}


int do_receive_program(struct program_header *hdr_out) {
    if (!hdr_out) return -3;

    program_armed = 0;

    int rc = loader_receive_to_staging(hdr_out);
    return rc;
}

/* Apply i386 dynamic relocations for a static-PIE (ET_DYN) image after its
 * segments have been copied into the task address space (still writable) and
 * before the W^X protection pass. Only R_386_RELATIVE (type 8) is implemented:
 * `*(u32*)(r_offset + slide) += slide`. Any other relocation type, a DT_RELA
 * table (i386 uses REL), an out-of-bounds table, or a target outside a loaded
 * segment causes a hard failure (fail closed) rather than a silently corrupt
 * image. `slide` is the load bias; seg_va[]/seg_memsz[] describe the mapped
 * segments (for target validation); the reloc table is read from the staging
 * file image, patches go through copy_from/to_user (current task == new task).
 * Returns 0 on success (including "no dynamic relocations"), negative on error. */
static int elf_apply_relocations_i386(const uint8_t *st, const uint8_t *ph,
                                      uint16_t e_phnum, uint32_t phentsize,
                                      uint32_t slide,
                                      const uint32_t *seg_va, const uint32_t *seg_memsz,
                                      int nseg) {
    /* Locate PT_DYNAMIC (p_type == 2). */
    uint32_t dyn_off = 0, dyn_sz = 0;
    for (uint16_t i = 0; i < e_phnum; i++) {
        const uint8_t *p = ph + (uint32_t)i * phentsize;
        uint32_t p_type = elf_rd32(p);
        if (p_type == 2) {                 /* PT_DYNAMIC */
            dyn_off = elf_rd32(p + 4);     /* p_offset (Elf32_Phdr) */
            dyn_sz  = elf_rd32(p + 16);    /* p_filesz */
            break;
        }
    }
    if (dyn_off == 0 || dyn_sz == 0) return 0;                 /* no dynamic info */
    if (dyn_off > MAX_PROGRAM_SIZE || dyn_sz > MAX_PROGRAM_SIZE ||
        dyn_off + dyn_sz > MAX_PROGRAM_SIZE) return -16;

    /* Walk Elf32_Dyn { int32 d_tag; uint32 d_val; } for the REL table. */
    uint32_t rel_vaddr = 0, rel_sz = 0, rel_ent = 8;
    for (uint32_t o = 0; o + 8 <= dyn_sz; o += 8) {
        int32_t  tag = (int32_t)elf_rd32(st + dyn_off + o);
        uint32_t val = elf_rd32(st + dyn_off + o + 4);
        if (tag == 0) break;               /* DT_NULL */
        else if (tag == 17) rel_vaddr = val;   /* DT_REL   */
        else if (tag == 18) rel_sz    = val;   /* DT_RELSZ */
        else if (tag == 19) rel_ent   = val;   /* DT_RELENT */
        else if (tag == 7)  return -16;        /* DT_RELA: unsupported on i386 */
    }
    if (rel_vaddr == 0 || rel_sz == 0) return 0;               /* no REL relocations */
    if (rel_ent != 8) return -16;

    /* Map the REL table's (link-time, base-0) vaddr to a file offset via the
     * PT_LOAD segment that contains it. */
    uint32_t rel_file_off = 0;
    int mapped = 0;
    for (uint16_t i = 0; i < e_phnum; i++) {
        const uint8_t *p = ph + (uint32_t)i * phentsize;
        if (elf_rd32(p) != 1) continue;    /* PT_LOAD */
        uint32_t p_offset = elf_rd32(p + 4);
        uint32_t p_vaddr  = elf_rd32(p + 8);
        uint32_t p_filesz = elf_rd32(p + 16);
        if (rel_vaddr >= p_vaddr && rel_vaddr < p_vaddr + p_filesz) {
            rel_file_off = p_offset + (rel_vaddr - p_vaddr);
            mapped = 1;
            break;
        }
    }
    if (!mapped) return -16;
    if (rel_file_off > MAX_PROGRAM_SIZE || rel_sz > MAX_PROGRAM_SIZE ||
        rel_file_off + rel_sz > MAX_PROGRAM_SIZE) return -16;

    uint32_t nrel = rel_sz / 8;
    if (nrel > 8192) return -16;           /* sane cap */
    for (uint32_t k = 0; k < nrel; k++) {
        const uint8_t *r = st + rel_file_off + (uint32_t)k * 8;
        uint32_t r_offset = elf_rd32(r);
        uint32_t r_info   = elf_rd32(r + 4);
        uint32_t r_type   = r_info & 0xFF;
        if (r_type == 0) continue;         /* R_386_NONE */
        if (r_type != 8) return -16;       /* only R_386_RELATIVE (fail closed) */

        uint32_t target = r_offset + slide;
        int in_seg = 0;
        for (int s = 0; s < nseg; s++) {
            if (target >= seg_va[s] && target + 4 <= seg_va[s] + seg_memsz[s]) { in_seg = 1; break; }
        }
        if (!in_seg) return -16;

        uint32_t w;
        if (copy_from_user(&w, (void *)(uintptr_t)target, 4) != 0) return -16;
        w += slide;
        if (copy_to_user((void *)(uintptr_t)target, &w, 4) != 0) return -16;
    }
    return 0;
}

int try_elf_load(uint32_t load_base, uint32_t *out_entry, uint32_t *out_img_end)
{
    if (!out_entry) return -1;
    const uint8_t *st = loader_staging;
    
    if (st[0] != 0x7f || st[1] != 'E' || st[2] != 'L' || st[3] != 'F') return -2;

    uint8_t ei_class = st[4]; 
    uint8_t ei_data  = st[5]; 
    if (ei_data != 1) return -3; 

    
    uint16_t e_type = (uint16_t)st[16] | ((uint16_t)st[17] << 8);
    uint16_t e_machine = (uint16_t)st[18] | ((uint16_t)st[19] << 8);
    uint32_t e_entry32 = 0;
    uint64_t e_entry64 = 0;
    uint32_t e_phoff = 0;
    uint16_t e_phnum = 0;

    if (ei_class == 1) { 
        if (e_machine != 3 ) return -4;
        e_entry32 = (uint32_t)st[24] | ((uint32_t)st[25]<<8) | ((uint32_t)st[26]<<16) | ((uint32_t)st[27]<<24);
        e_phoff   = (uint32_t)st[28] | ((uint32_t)st[29]<<8) | ((uint32_t)st[30]<<16) | ((uint32_t)st[31]<<24);
        e_phnum   = (uint16_t)st[44] | ((uint16_t)st[45] << 8);
    } else if (ei_class == 2) { 
        if (e_machine != 62 ) return -4;
        e_entry64 = (uint64_t)st[24] | ((uint64_t)st[25]<<8) | ((uint64_t)st[26]<<16) | ((uint64_t)st[27]<<24) |
                    ((uint64_t)st[28]<<32) | ((uint64_t)st[29]<<40) | ((uint64_t)st[30]<<48) | ((uint64_t)st[31]<<56);
        e_phoff   = (uint32_t)st[32] | ((uint32_t)st[33]<<8) | ((uint32_t)st[34]<<16) | ((uint32_t)st[35]<<24);
        e_phnum   = (uint16_t)st[56] | ((uint16_t)st[57] << 8);
    } else {
        return -5;
    }

    if (e_type != 2  && e_type != 3 ) return -6;
    if (e_phnum == 0 || e_phnum > 8) return -7; 
    if (e_phoff == 0 || e_phoff > (MAX_PROGRAM_SIZE - 64)) return -8;

    
    uint32_t min_vaddr = 0xFFFFFFFFU;
    int have_load = 0;
    const uint8_t *ph = st + e_phoff;
    uint32_t phentsize = (ei_class == 1) ? 32 : 56;

    for (uint16_t i = 0; i < e_phnum; i++) {
        const uint8_t *p = ph + (uint32_t)i * phentsize;
        uint32_t p_type = p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
        if (p_type != 1 ) continue;
        uint32_t p_vaddr;
        if (ei_class == 1) {
            p_vaddr = (uint32_t)p[8] | ((uint32_t)p[9]<<8) | ((uint32_t)p[10]<<16) | ((uint32_t)p[11]<<24);
        } else {
            p_vaddr = (uint32_t)p[16] | ((uint32_t)p[17]<<8) | ((uint32_t)p[18]<<16) | ((uint32_t)p[19]<<24);
        }
        if (p_vaddr < min_vaddr) min_vaddr = p_vaddr;
        have_load = 1;
    }
    if (!have_load) return -9;

    uint32_t slide = load_base - (min_vaddr & ~0xFFFU);

    /* Record each loaded segment's mapped range and ELF p_flags so that, after
     * the bytes are copied in (which needs the pages writable), we can apply
     * W^X per page: code becomes read+execute, data/rodata read[+write]+NX.
     * e_phnum is capped at 8 above, so PT_LOAD segments fit in these arrays. */
    uint32_t seg_va[8], seg_memsz[8], seg_flags[8];
    int nseg = 0;
    uint32_t max_va_end = 0;

    for (uint16_t i = 0; i < e_phnum; i++) {
        const uint8_t *p = ph + (uint32_t)i * phentsize;
        uint32_t p_type = p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
        if (p_type != 1) continue;

        uint32_t p_offset=0, p_vaddr=0, p_filesz=0, p_memsz=0, p_flags=0;
        if (ei_class == 1) {
            p_offset = (uint32_t)p[4] | ((uint32_t)p[5]<<8) | ((uint32_t)p[6]<<16) | ((uint32_t)p[7]<<24);
            p_vaddr  = (uint32_t)p[8] | ((uint32_t)p[9]<<8) | ((uint32_t)p[10]<<16) | ((uint32_t)p[11]<<24);
            p_filesz = (uint32_t)p[16]| ((uint32_t)p[17]<<8)| ((uint32_t)p[18]<<16)| ((uint32_t)p[19]<<24);
            p_memsz  = (uint32_t)p[20]| ((uint32_t)p[21]<<8)| ((uint32_t)p[22]<<16)| ((uint32_t)p[23]<<24);
            p_flags  = (uint32_t)p[24]| ((uint32_t)p[25]<<8)| ((uint32_t)p[26]<<16)| ((uint32_t)p[27]<<24);
        } else {
            p_offset = (uint32_t)p[8] | ((uint32_t)p[9]<<8) | ((uint32_t)p[10]<<16) | ((uint32_t)p[11]<<24);
            p_vaddr  = (uint32_t)p[16]| ((uint32_t)p[17]<<8)| ((uint32_t)p[18]<<16)| ((uint32_t)p[19]<<24);
            p_filesz = (uint32_t)p[32]| ((uint32_t)p[33]<<8)| ((uint32_t)p[34]<<16)| ((uint32_t)p[35]<<24);
            p_memsz  = (uint32_t)p[40]| ((uint32_t)p[41]<<8)| ((uint32_t)p[42]<<16)| ((uint32_t)p[43]<<24);
            p_flags  = (uint32_t)p[4] | ((uint32_t)p[5]<<8)| ((uint32_t)p[6]<<16)| ((uint32_t)p[7]<<24);
        }

        if (p_memsz < p_filesz) return -10;
        if (p_offset + p_filesz > MAX_PROGRAM_SIZE) return -11;
        uint32_t dest_va = p_vaddr + slide;
        uint32_t va_end = dest_va + p_memsz;
        if (va_end > max_va_end) max_va_end = va_end;
        if (dest_va < USER_AREA_BASE || dest_va >= USER_MAX_VADDR) return -12;
        if (dest_va + p_memsz < dest_va) return -13; 

        /* Copy the segment's file bytes, then zero-fill the BSS tail, into
         * the target task's address space (current task == new_id here).
         * copy_to_user walks the page tables with present/user/write checks,
         * handles huge pages, switches to the kernel CR3 (SMAP-safe), and
         * fails closed on any unmapped page -- unlike the previous
         * hand-rolled walk, which masked each level without a present-bit
         * check and would dereference and write a garbage ring-0 physical
         * address for any non-present or huge-page mapping. */
        static const uint8_t elf_zero_fill[4096] = {0};
        const uint8_t *s = st + p_offset;
        for (uint32_t off = 0; off < p_filesz; ) {
            uint32_t chunk = p_filesz - off;
            if (chunk > USER_MEM_MAX_COPY) chunk = USER_MEM_MAX_COPY;
            if (copy_to_user((void *)(uintptr_t)(dest_va + off), s + off, chunk) != 0)
                return -15;
            off += chunk;
        }
        for (uint32_t off = p_filesz; off < p_memsz; ) {
            uint32_t chunk = p_memsz - off;
            if (chunk > sizeof(elf_zero_fill)) chunk = sizeof(elf_zero_fill);
            if (copy_to_user((void *)(uintptr_t)(dest_va + off), elf_zero_fill, chunk) != 0)
                return -15;
            off += chunk;
        }

        if (nseg < 8) {
            seg_va[nseg]    = dest_va;
            seg_memsz[nseg] = p_memsz;
            seg_flags[nseg] = p_flags;
            nseg++;
        }
    }

    /* Apply dynamic relocations for a PIE image while the pages are still
     * writable. i386 static-PIE uses R_386_RELATIVE (or, commonly, none at all
     * thanks to GOTOFF addressing). A 64-bit PIE would need R_X86_64_RELATIVE,
     * which is not implemented -- fail closed rather than run it unrelocated. */
    if (ei_class == 1) {
        int rrc = elf_apply_relocations_i386(st, ph, e_phnum, phentsize, slide,
                                             seg_va, seg_memsz, nseg);
        if (rrc != 0) return rrc;
    } else if (e_type == 3) {   /* ET_DYN, 64-bit: unsupported */
        return -16;
    }

    /* W^X protection pass. Every page touched by a PT_LOAD segment is set to
     * the union of the permissions of the segments covering it (so a page
     * shared between, say, the end of .text and the start of .rodata keeps
     * whatever each needs). PF_W (0x2) -> writable, PF_X (0x1) -> executable;
     * absence of PF_X sets NX. The pages were just written via copy_to_user so
     * they are present; user_protect_page only downgrades permission bits. */
    for (int s = 0; s < nseg; s++) {
        uint32_t pstart = seg_va[s] & ~0xFFFu;
        uint32_t pend   = seg_va[s] + seg_memsz[s];
        for (uint32_t va = pstart; va < pend; va += 0x1000) {
            int writable = 0, executable = 0;
            for (int k = 0; k < nseg; k++) {
                uint32_t kstart = seg_va[k] & ~0xFFFu;
                uint32_t kend   = seg_va[k] + seg_memsz[k];
                if (va < kend && va + 0x1000u > kstart) {   /* page overlaps seg k */
                    if (seg_flags[k] & 0x2u) writable = 1;  /* PF_W */
                    if (seg_flags[k] & 0x1u) executable = 1;/* PF_X */
                }
            }
            user_protect_page((uint64_t)va, writable, executable);
        }
    }

    uint64_t final_entry = (ei_class == 1) ? ((uint64_t)e_entry32 + slide) : (e_entry64 + slide);
    if (final_entry >= USER_MAX_VADDR) return -14;
    *out_entry = (uint32_t)final_entry;
    if (out_img_end) *out_img_end = max_va_end;
    return 0;
}

/* Pick the ASLR image base + stack top for the currently-armed staged image
 * about to be loaded into task `tid`. PIE (ET_DYN) ELF images are relocated by
 * try_elf_load and get a randomized, page-aligned, bounded base; non-PIE flat
 * images keep the fixed USER_AREA_BASE (their addresses are baked in). Shared by
 * spawn (tid = a fresh slot) and exec (tid = the current task). */
void choose_image_placement(int tid, uint32_t *out_load_base, uint32_t *out_stack_top) {
    uint64_t spawn_entropy = (uint64_t)armed_hdr.size;
    spawn_entropy ^= (uint64_t)armed_hdr.entry << 17;
    spawn_entropy ^= (uint64_t)tid * 0x9E3779B97F4A7C15ULL;
    spawn_entropy ^= (uint64_t)get_system_ticks() << 11;
    spawn_entropy ^= (uint64_t)get_current_task();
    spawn_entropy ^= read_tsc();
    spawn_entropy ^= rust_rng_u64();

    aslr_mix_entropy(spawn_entropy);

    int staged_is_elf = (armed_hdr.size >= 4 &&
                         loader_staging[0] == 0x7f && loader_staging[1] == 'E' &&
                         loader_staging[2] == 'L' && loader_staging[3] == 'F');

    /* Bound the image-base ASLR so the premap window (base + PREMAP pages, mapped
     * as USER by create_user_pagedir) can never reach the kernel's own writable
     * globals. The kernel is linked low and its BSS extends above USER_AREA_BASE,
     * so an unbounded window could land over tasks[]/scheduler state; a kernel
     * read of that data on the task's CR3 would then return the task's (zeroed)
     * user page and corrupt the scheduler. kernel_bss_floor is the link-time start
     * of .bss (see linker64.ld). */
    extern uint8_t kernel_bss_floor[];
    uint32_t eff_max_pages = ASLR_MAX_LOAD_RANDOM_PAGES;
    uint32_t window_bytes  = (uint32_t)USER_ASPACE_PREMAP_PAGES * PAGE_SIZE;
    uint32_t floor         = (uint32_t)(uintptr_t)kernel_bss_floor;
    if (floor > USER_AREA_BASE + window_bytes) {
        uint32_t safe_pages = (floor - window_bytes - (uint32_t)USER_AREA_BASE) / PAGE_SIZE;
        if (safe_pages < eff_max_pages) eff_max_pages = safe_pages;
    } else {
        eff_max_pages = 0;   /* no safe room below the kernel data: pin at the base */
    }

    uint32_t load_base = USER_AREA_BASE;
    if (staged_is_elf && eff_max_pages > 0) {
        load_base = (uint32_t)(USER_AREA_BASE + aslr_random_offset(eff_max_pages));
        load_base &= ~0xFFFu;
    }

    *out_load_base  = load_base;
    *out_stack_top  = (uint32_t)aslr_random_stack_top(0x007ff000u);
}

/* Load the currently-armed staged image into task `tid`'s (already-built)
 * address space: run the ELF loader (or the flat-image fallback), then set
 * eip/image_end/heap/name and disarm the loader. Makes `tid` the current task so
 * the loader's copy_to_user writes into its address space. Shared by spawn and
 * exec; the caller is responsible for building the address space beforehand
 * (create_task for spawn, create_user_pagedir for exec). */
void load_staged_image_into(int tid, uint32_t load_base) {
    set_current_task(tid);

    uint32_t entry_point = armed_hdr.entry;
    uint32_t elf_entry = 0;
    uint32_t elf_img_end = 0;
    int elf_rc = try_elf_load(load_base, &elf_entry, &elf_img_end);
    int elf_loaded = (elf_rc == 0);
#ifdef NEWLIB_SELFTEST
    print("do_spawn: elf_rc="); print_hex((uint64_t)(uint32_t)elf_rc);
    print(" elf_entry="); print_hex(elf_entry); print("\n");
#endif
    if (elf_loaded) {
        entry_point = elf_entry;
    } else {

        uint32_t copy_sz = armed_hdr.size;
        if (copy_sz > 0x200000) copy_sz = 0x200000;
        extern platform_info_t platform;
        uint64_t tcr30 = tasks[get_current_task()].cr3;
        if (platform.has_smap) { asm volatile("clac" ::: "memory"); }
        for (uint32_t off = 0; off < copy_sz; ) {
            uint32_t va = load_base + off;
            uint64_t dphys = (uint64_t)va;
            if (tcr30) {
                uint64_t *p4 = (uint64_t *)tcr30;
                uint64_t ii4 = ((uint64_t)va >> 39) & 0x1ff;
                uint64_t ee4 = p4[ii4];
                if (ee4 & 1) {
                    uint64_t *pp3 = (uint64_t *)(ee4 & ~0xfffULL);
                    uint64_t ii3 = ((uint64_t)va >> 30) & 0x1ff;
                    uint64_t ee3 = pp3[ii3];
                    if (ee3 & 1) {
                        uint64_t *pp2 = (uint64_t *)(ee3 & ~0xfffULL);
                        uint64_t ii2 = ((uint64_t)va >> 21) & 0x1ff;
                        uint64_t ee2 = pp2[ii2];
                        if (ee2 & 1) {
                            if (ee2 & (1ULL << 7)) {
                                dphys = (ee2 & ~0x1fffffULL) | ((uint64_t)va & 0x1fffffULL);
                            } else {
                                uint64_t *pp1 = (uint64_t *)(ee2 & ~0xfffULL);
                                uint64_t ii1 = ((uint64_t)va >> 12) & 0x1ff;
                                uint64_t ee1 = pp1[ii1];
                                if (ee1 & 1) {
                                    dphys = (ee1 & ~0xfffULL) | ((uint64_t)va & 0xfffULL);
                                }
                            }
                        }
                    }
                }
            }
            /* If the page walk above did not find a present mapping, dphys was
             * left equal to va (a user virtual address). Writing to that value
             * as a physical address would silently corrupt kernel memory at
             * physical va. Skip the copy for unmapped pages rather than
             * writing to the wrong physical location. */
            if (dphys == (uint64_t)va) { off += 4096; continue; }
            uint8_t *d = (uint8_t *)dphys;
            uint32_t poff = va & 0xfff;
            uint32_t chunk = 4096 - poff;
            if (chunk > copy_sz - off) chunk = copy_sz - off;
            for (uint32_t i = 0; i < chunk; i++) d[i] = loader_staging[off + i];
            off += chunk;
        }
        if (platform.has_smap) { asm volatile("stac" ::: "memory"); }
    }


    tasks[tid].eip = elf_loaded ? entry_point : (load_base + entry_point);

    /* For ELF loads, image_end must come from the actual highest PT_LOAD
     * vaddr+memsz (accounts for ASLR slide and .bss extending past filesz);
     * armed_hdr.size is the raw staged file size and undercounts .bss. */
    uint32_t img_end = elf_loaded
        ? ((elf_img_end + 0xFFF) & ~0xFFFu)
        : (load_base + ((armed_hdr.size + 0xFFF) & ~0xFFF));
    tasks[tid].image_end = img_end;
    uint32_t heap_gap = aslr_random_offset(ASLR_MAX_HEAP_GAP_PAGES);
    tasks[tid].heap_start   = img_end + 0x1000 + heap_gap;
    tasks[tid].heap_current = tasks[tid].heap_start;
    tasks[tid].heap_end     = tasks[tid].heap_start + 0x10000;

    if (armed_hdr.name[0] != 0) {
        int k = 0;
        while (k < 31 && armed_hdr.name[k]) {
            tasks[tid].name[k] = armed_hdr.name[k];
            k++;
        }
        tasks[tid].name[k] = 0;
    } else {
        tasks[tid].name[0] = 'p'; tasks[tid].name[1] = 'r';
        tasks[tid].name[2] = 'o'; tasks[tid].name[3] = 'g';
        tasks[tid].name[4] = '0' + tid; tasks[tid].name[5] = 0;
    }

    program_armed = 0;
}

/* --- spawn argument vector staging ------------------------------------------
 * h_spawn copies the spawner's argv strings here (read from the spawner's own
 * address space) before the child is built; do_spawn_inner then marshals them
 * onto the child's initial stack once its address space exists. */

