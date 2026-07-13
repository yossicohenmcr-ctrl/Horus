#include "kernel.h"

extern uint8_t stack_top[];
extern tcb_t tasks[MAX_TASKS];

#define PAGE_PRESENT   (1 << 0)
#define PAGE_WRITE     (1 << 1)
#define PAGE_USER      (1 << 2)
#define PAGE_WT        (1 << 3)
#define PAGE_CD        (1 << 4)
#define PAGE_ACCESSED  (1 << 5)
#define PAGE_DIRTY     (1 << 6)
#define PAGE_4MB       (1 << 7)
#define PAGE_GLOBAL    (1 << 8)
#define PAGE_COW       (1 << 9)
/* No-execute (bit 63). EFER.NXE is enabled in multiboot.S, so the CPU honours
 * it on 64-bit page-table entries. Used to map user stacks non-executable
 * (W^X): data pages must never be executable, defeating classic shellcode on
 * the stack. The image/heap region stays executable because the flat-binary
 * loader cannot tell code from data within it. */
#define PAGE_NX        (1ULL << 63)

/* The W^X "is this user page non-executable?" policy lives in Rust
 * (rust_user_page_is_noexec); the kernel ORs PAGE_NX into the PTE when it
 * returns true. See rust/src/lib.rs. */

#define RECURSIVE_PD_VADDR  0xFFFFF000
#define RECURSIVE_PT_VADDR  0xFFC00000

#define RECURSIVE_PML4_VADDR  0xFFFFFFFFFFFFF000ULL
#define RECURSIVE_PDPT_VADDR  0xFFFFFFFFFFE00000ULL
#define RECURSIVE_PD_VADDR64  0xFFFFFFFFC0000000ULL
#define RECURSIVE_PT_VADDR64  0xFFFFFF8000000000ULL



typedef uint32_t pte_t;
typedef uint32_t pde_t;

static uint32_t free_page_stack[USER_PHYS_PAGES];
static int free_page_count = 0;
static uint16_t page_refcounts[USER_PHYS_PAGES];

uint32_t get_free_user_pages(void) { return (uint32_t)free_page_count; }

static void init_user_page_allocator(void) {

    free_page_count = 0;
    for (int i = 0; i < USER_PHYS_PAGES; i++) {
        page_refcounts[i] = 0;
    }
    for (int i = USER_PHYS_PAGES - 1; i >= 0; i--) {
        free_page_stack[free_page_count++] = USER_PHYS_BASE + (i * PAGE_SIZE);
    }
    /* Register the one true refcount table with the Rust trust boundary so any
     * later inc/dec passing a wrong pointer/size is refused rather than trusted. */
    if (!rust_page_refcounts_register(page_refcounts, (uint32_t)USER_PHYS_PAGES)) {
        for (;;) { __asm__ volatile("cli; hlt"); }  /* misconfiguration: refuse to run */
    }
}

uint32_t alloc_user_physical_page(void) {
    
    if (free_page_count == 0) {
        return 0;
    }
    uint32_t phys = free_page_stack[--free_page_count];
    int idx = (phys - USER_PHYS_BASE) / PAGE_SIZE;
    if (idx >= 0 && idx < USER_PHYS_PAGES) {
        page_refcounts[idx] = 1;
    }
    return phys;
}

void free_user_physical_page(uint32_t phys_addr) {
    int idx = (phys_addr - USER_PHYS_BASE) / PAGE_SIZE;
    if (idx >= 0 && idx < USER_PHYS_PAGES) {
        page_refcounts[idx] = 0;
    }
    if (free_page_count < USER_PHYS_PAGES) {
        free_page_stack[free_page_count++] = phys_addr;
    }
}

void page_ref_inc(uint32_t phys_addr) {
    int idx = (phys_addr - USER_PHYS_BASE) / PAGE_SIZE;
    if (idx >= 0 && idx < USER_PHYS_PAGES) {
        page_refcounts[idx]++;
    }
}

int page_ref_dec(uint32_t phys_addr) {
    int idx = (phys_addr - USER_PHYS_BASE) / PAGE_SIZE;
    if (idx >= 0 && idx < USER_PHYS_PAGES && page_refcounts[idx] > 0) {
        page_refcounts[idx]--;
        return page_refcounts[idx];
    }
    return 0;
}

static pde_t kernel_page_dir[1024] __attribute__((used, aligned(4096)));


void ensure_lapic_mapped(uint64_t *root);

void paging_init(void) {
    init_user_page_allocator();
    set_tss_kernel_stack(KERNEL_TSS_STACK);
    extern platform_info_t platform;
    if (platform.has_smap) {
        uint64_t cr4;
        asm volatile("mov %%cr4, %0" : "=r"(cr4));
        cr4 |= (1ULL << 21);
        asm volatile("mov %0, %%cr4" :: "r"(cr4) : "memory");
    }
    extern uint64_t pml4[512];
    if ((pml4[510] & 0x1) == 0) {
        pml4[510] = ((uint64_t)pml4) | 0x3;
    }
    ensure_lapic_mapped(NULL);
    return;
}

/* Per-task kernel stacks. Big (4 MiB) .bss array; because the kernel is linked
 * low, it lands around [1.46, 5.43) MiB — its tail overlaps the low user-image
 * window. Its top edge is also the floor of the kernel's *always-critical* global
 * data (page tables, tasks[], cspaces, locks), which is placed above it and must
 * never be shadowed by a user mapping. kernel_lowmem_critical_floor() exposes that
 * edge so the heap allocator can refuse to grow a user heap up into it. */
static uint8_t per_task_kstacks[MAX_TASKS][KERNEL_STACK_SIZE * 2] __attribute__((aligned(4096)));

/* Lowest kernel virtual address whose contents the kernel reads/writes while
 * running on a *user* CR3 and that a user low-memory mapping must therefore never
 * be allowed to overlay. Everything at or above this is always-live kernel state;
 * below it (within the user window) lies only unused high-id kstack slots. */
uint32_t kernel_lowmem_critical_floor(void) {
    return (uint32_t)((uintptr_t)per_task_kstacks + sizeof(per_task_kstacks));
}

void create_user_pagedir(uint32_t task_id) {
    if (task_id >= MAX_TASKS) return;
    if (task_id == 0) {
        tasks[task_id].cr3 = 0;
        return;
    }

    spin_lock(&page_lock);
    
    uint64_t pml4_phys = alloc_user_physical_page();
    if (pml4_phys == 0) { println("pagedir: no pml4 phys"); spin_unlock(&page_lock); return; }
    uint64_t *pml4_tab = (uint64_t *)(uintptr_t)pml4_phys;
    for (int i = 0; i < 512; i++) pml4_tab[i] = 0;

    
    pml4_tab[510] = pml4_phys | PAGE_PRESENT | PAGE_WRITE;

    extern uint64_t pml4[512];

    
    for (int i = 0; i < 256; i++) {
        pml4_tab[i] = 0;
    }
    
    for (int i = 256; i < 512; i++) {
        pml4_tab[i] = pml4[i] & ~((uint64_t)PAGE_USER);
        pml4_tab[i] &= ~(1ULL << 2);
    }

    
    uint64_t pdpt_phys = alloc_user_physical_page();
    if (pdpt_phys == 0) { println("pagedir: no pdpt phys"); spin_unlock(&page_lock); return; }
    uint64_t *my_pdpt = (uint64_t *)(uintptr_t)pdpt_phys;
    for (int j = 0; j < 512; j++) my_pdpt[j] = 0;

    uint64_t pd_phys = alloc_user_physical_page();
    if (pd_phys == 0) { println("pagedir: no pd phys"); spin_unlock(&page_lock); return; }
    uint64_t *my_pd = (uint64_t *)(uintptr_t)pd_phys;
    for (int j = 0; j < 512; j++) my_pd[j] = 0;

    
    uint64_t my_pd_phys = pd_phys;
    my_pdpt[0] = my_pd_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;

    for (int kp = 0; kp < 8; kp++) {
        if (my_pd[kp] == 0) {
            uint64_t base = (uint64_t)kp * 0x200000ULL;
            my_pd[kp] = base | PAGE_PRESENT | PAGE_WRITE | (1 << 7);
        }
    }

    
    
    
    
    

    int pages_to_map = (int)USER_ASPACE_PREMAP_PAGES;
    /* Premap the image window at the task's (possibly ASLR-randomized) base.
     * ASLR_MAX_LOAD_RANDOM_PAGES bounds the base so [base, base+premap) lies
     * within a single 2 MiB PD entry, so a single page table covers the image
     * and the PT index is derived from the real virtual address (not the loop
     * counter, which would only be correct for a 2 MiB-aligned base). */
    uint64_t vbase = tasks[task_id].image_base ? (uint64_t)tasks[task_id].image_base
                                               : (uint64_t)USER_AREA_BASE;
    int pdi      = (int)((vbase >> 21) & 511);
    int base_pti = (int)((vbase >> 12) & 511);

    uint64_t *cur_pt = 0;
    if (pdi < 512) {
        /* Replace the 2 MiB huge-page mapping installed above for this PD entry
         * with a fine-grained page table. Identity-fill it (supervisor, as
         * before) so the non-image pages of the 2 MiB region stay mapped, then
         * map the image pages as USER at the randomized base offset. */
        uint64_t pt_phys = alloc_user_physical_page();
        if (pt_phys) {
            cur_pt = (uint64_t *)pt_phys;
            uint64_t region_base = (uint64_t)pdi * 0x200000ULL;
            for (int k = 0; k < 512; k++)
                cur_pt[k] = (region_base + (uint64_t)k * PAGE_SIZE) | PAGE_PRESENT | PAGE_WRITE;
            my_pd[pdi] = pt_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
        }
    }

    for (int p = 0; p < pages_to_map && cur_pt; p++) {
        int pt_idx = base_pti + p;
        if (pt_idx >= 512) break;   /* window stays within one PD (base is bounded) */

        uint64_t phys = alloc_user_physical_page();
        if (phys == 0) break;

        uint8_t *pg = (uint8_t *)phys;
        for (int b = 0; b < PAGE_SIZE; b++) pg[b] = 0;

        uint32_t prot = rust_get_user_page_protection(task_id, (uint32_t)(vbase + (uint64_t)p * PAGE_SIZE));
        uint64_t flags = prot ? (prot & 0x7) : (PAGE_PRESENT | PAGE_WRITE | PAGE_USER);
        cur_pt[pt_idx] = phys | flags;
    }

    
    uint64_t hs_base = (ASLR_HIGH_STACK_BASE - (32 * PAGE_SIZE)) & ~0xFFFULL;
    int hs_pdi = (int)((hs_base >> 21) & 511);
    if (hs_pdi < 512 && my_pd[hs_pdi] == 0) {
        uint64_t pt_phys = alloc_user_physical_page();
        if (pt_phys) {
            uint64_t *pt = (uint64_t *)pt_phys;
            for (int k = 0; k < 512; k++) pt[k] = 0;
            my_pd[hs_pdi] = pt_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;

            
            for (int s = 0; s < 64; s++) {
                uint64_t phys = alloc_user_physical_page();
                if (phys == 0) break;
                uint8_t *pg = (uint8_t *)phys; for (int b = 0; b < PAGE_SIZE; b++) pg[b] = 0;
                int spti = ((hs_base + (uint64_t)s * PAGE_SIZE) >> 12) & 511;
                uint32_t prot = rust_get_user_page_protection(task_id, (uint32_t)(hs_base + (uint64_t)s * PAGE_SIZE));
                uint64_t flags = prot ? (prot & 0x7) : (PAGE_PRESENT | PAGE_WRITE | PAGE_USER);
                /* High ASLR stack: non-executable (W^X). */
                pt[spti] = phys | flags | PAGE_NX;
            }
        }
    }

    
    {
        uint64_t low_stack_top = 0x007ff000ULL;
        uint64_t low_stack_base = low_stack_top - (32ULL * PAGE_SIZE);
        int ls_pdi = (int)((low_stack_base >> 21) & 511);
        if (ls_pdi < 512) {
            uint64_t pt_phys = alloc_user_physical_page();
            if (pt_phys) {
                uint64_t *pt = (uint64_t *)pt_phys;

                uint64_t ls_region_base = (uint64_t)ls_pdi * 0x200000ULL;
                for (int k = 0; k < 512; k++)
                    pt[k] = (ls_region_base + (uint64_t)k * PAGE_SIZE) | PAGE_PRESENT | PAGE_WRITE;
                my_pd[ls_pdi] = pt_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
                for (int s = 0; s < 32; s++) {
                    uint64_t phys = alloc_user_physical_page();
                    if (phys == 0) break;
                    uint8_t *pg = (uint8_t *)(uintptr_t)phys;
                    for (int b = 0; b < PAGE_SIZE; b++) pg[b] = 0;
                    uint64_t va = low_stack_base + (uint64_t)s * PAGE_SIZE;
                    int spti = (int)((va >> 12) & 511);
                    /* Low user stack: non-executable (W^X). */
                    pt[spti] = phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER | PAGE_NX;
                }
            }
        }
    }

    uint64_t my_pdpt_phys = pdpt_phys;
    
    pml4_tab[0] = my_pdpt_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;

    
    pml4_tab[510] = pml4_phys | PAGE_PRESENT | PAGE_WRITE;

    ensure_lapic_mapped(pml4_tab);

    tasks[task_id].cr3 = pml4_phys;

    
    /* The stack must be large enough for the deepest in-kernel call chain —
     * notably the Argon2id password hash run from SYS_AUTH, which stacks several
     * 1 KiB blocks and overflowed the old 8 KiB stack (login hung). */
    uint8_t *stack_area = per_task_kstacks[task_id];
    uint64_t guard_vaddr = (uint64_t)stack_area;
    uint64_t stack_base = guard_vaddr + PAGE_SIZE;
    tasks[task_id].kernel_stack_top = stack_base + KERNEL_STACK_SIZE - 16;
    spin_unlock(&page_lock);
}

void switch_cr3(addr_t cr3) {
    
    if (cr3 == 0) {
        
        for(;;) { asm volatile("cli; hlt"); }
    }
    
    if ((cr3 & 0xFFFULL) != 0) {
        for(;;) { asm volatile("cli; hlt"); }
    }
    asm volatile("mov %0, %%cr3" :: "r"(cr3) : "memory");
    /* The CR3 reload above already flushed this CPU's non-global TLB entries, so
     * a purely local address-space switch needs no cross-CPU shootdown. (A real
     * shootdown -- for tearing down or reducing permissions on a mapping another
     * CPU may have cached -- goes through smp_maybe_shootdown at that site, with
     * interrupts enabled and no scheduler lock held, so its ack wait is safe.) */
}

int handle_demand_page_fault(uint32_t fault_addr, uint32_t err_code) {
    
    uint64_t cr3_phys = tasks[get_current_task()].cr3;
    if (cr3_phys == 0) {
        /* page_lock is NOT held yet (we lock below), so must not unlock here:
         * a stray spin_unlock releases a lock we never took and decrements the
         * IRQ-nesting depth, corrupting interrupt state if ever reached under a
         * held lock. */
        int tid = get_current_task();
        tasks[tid].state = 0;
        return -1;
    }

    spin_lock(&page_lock);

    uint64_t *pml4v = (uint64_t *)cr3_phys;

    uint64_t v = fault_addr;
    uint64_t pml4_i = (v >> 39) & 0x1FF;
    uint64_t pdpt_i = (v >> 30) & 0x1FF;
    uint64_t pd_i   = (v >> 21) & 0x1FF;
    uint64_t pt_i   = (v >> 12) & 0x1FF;

    uint64_t pml4e = pml4v[pml4_i];
    if ((pml4e & PAGE_PRESENT) == 0) { spin_unlock(&page_lock); return -1; }
    uint64_t *pdptv = (uint64_t *)(pml4e & ~0xFFFULL);

    uint64_t pdpte = pdptv[pdpt_i];
    if ((pdpte & PAGE_PRESENT) == 0) {
        
        uint64_t new_pd_phys = alloc_user_physical_page();
        if (new_pd_phys == 0) { spin_unlock(&page_lock); return -3; }
        uint64_t *new_pd = (uint64_t *)new_pd_phys;
        for (int i = 0; i < 512; i++) new_pd[i] = 0;
        pdptv[pdpt_i] = new_pd_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
        pdpte = pdptv[pdpt_i];
        asm volatile("invlpg (%0)" :: "r"(v) : "memory");
    }
    uint64_t *pdv = (uint64_t *)(pdpte & ~0xFFFULL);

    uint64_t pde = pdv[pd_i];
    if ((pde & PAGE_PRESENT) == 0) {
        
        uint64_t new_pt_phys = alloc_user_physical_page();
        if (new_pt_phys == 0) { spin_unlock(&page_lock); return -3; }
        uint64_t *new_pt = (uint64_t *)new_pt_phys;
        for (int i = 0; i < 512; i++) new_pt[i] = 0;
        pdv[pd_i] = new_pt_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
        pde = pdv[pd_i];
        asm volatile("invlpg (%0)" :: "r"(v) : "memory");
    }
    uint64_t *ptv = (uint64_t *)(pde & ~0xFFFULL);

    uint64_t pte = ptv[pt_i];

    int is_write = (err_code & 2) != 0;

    if (is_write && (pte & PAGE_COW) != 0) {
        uint64_t old_phys = pte & ~0xFFFULL;

        
        int refs = rust_page_ref_dec((uint32_t)old_phys,
                                     page_refcounts,
                                     (uint32_t)USER_PHYS_PAGES);

        
        int is_write_f = 1;
        if (!rust_cow_copy_required(true, is_write_f != 0, (uint16_t)((refs > 0 ? refs : 0) + 1))) {
            if (refs >= 0) {
                (void)rust_page_ref_inc((uint32_t)old_phys,
                                        page_refcounts,
                                        (uint32_t)USER_PHYS_PAGES);
            }
            spin_unlock(&page_lock);
            return 0;
        }

        uint64_t new_phys = alloc_user_physical_page();
        if (new_phys == 0) {
            if (refs >= 0) {
                (void)rust_page_ref_inc((uint32_t)old_phys,
                                        page_refcounts,
                                        (uint32_t)USER_PHYS_PAGES);
            }
            spin_unlock(&page_lock);
            return -3;
        }

        uint8_t *src = (uint8_t *)(addr_t)old_phys;
        uint8_t *dst = (uint8_t *)(addr_t)new_phys;
        for (int i = 0; i < PAGE_SIZE; i++) dst[i] = src[i];

        (void)rust_page_ref_inc((uint32_t)new_phys,
                                page_refcounts,
                                (uint32_t)USER_PHYS_PAGES);

        uint64_t new_flags = (pte & 0xFFFULL) | PAGE_PRESENT | PAGE_WRITE;
        new_flags &= ~((uint64_t)PAGE_COW);
        /* Preserve W^X across copy-on-write: the low-12-bit mask above drops
         * the NX bit (63), so re-derive it from the faulting address. */
        if (rust_user_page_is_noexec(fault_addr)) new_flags |= PAGE_NX;
        ptv[pt_i] = new_phys | new_flags;

        asm volatile("invlpg (%0)" :: "r"(fault_addr) : "memory");
        spin_unlock(&page_lock);
        return 0;
    }

    if ((pte & PAGE_PRESENT) != 0) {
        
        spin_unlock(&page_lock);
        return -2;
    }

    
    uint64_t phys = alloc_user_physical_page();
    if (phys == 0) {
        spin_unlock(&page_lock);
        return -3;
    }

    uint8_t *page = (uint8_t *)(addr_t)phys;
    for (int i = 0; i < PAGE_SIZE; i++) page[i] = 0;

    uint32_t prot = rust_get_user_page_protection(get_current_task(), fault_addr);
    uint64_t flags = prot ? (prot & 0x7ULL) : (PAGE_PRESENT | PAGE_WRITE | PAGE_USER);
    /* Demand-paged stack pages are non-executable (W^X). */
    if (rust_user_page_is_noexec(fault_addr)) flags |= PAGE_NX;
    ptv[pt_i] = phys | flags | PAGE_PRESENT;

    asm volatile("invlpg (%0)" :: "r"(fault_addr) : "memory");
    spin_unlock(&page_lock);
    return 0;
}

void drop_to_ring3(addr_t entry, addr_t stack) {
    __asm__ volatile ("movw $0x3f8,%%dx; movb $'E',%%al; outb %%al,%%dx; movb $'N',%%al; outb %%al,%%dx; movb $'T',%%al; outb %%al,%%dx" ::: "rax","rdx","memory");
    asm volatile (
        "cli\n"
        "mov $0x33, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "mov %%ax, %%fs\n"
        "mov %%ax, %%gs\n"
        "push $0x33\n"
        "push %[user_rsp]\n"
        "push $0x202\n"
        "push $0x2b\n"
        "push %[user_rip]\n"
        "iretq\n"
        :
        : [user_rsp] "r" (stack),
          [user_rip] "r" (entry)
        : "memory", "rax"
    );
}

static bool is_canonical_address(uint64_t addr) {
    uint64_t high_bits = addr >> 48;
    return (high_bits == 0) || (high_bits == 0xFFFF);
}

#define PT_PHYS_MASK 0x000FFFFFFFFFF000ULL


static uint64_t pt_walk(uint64_t cr3, uint64_t v) {
    uint64_t *t = (uint64_t *)(uintptr_t)(cr3 & PT_PHYS_MASK);
    uint64_t e = t[(v >> 39) & 0x1FF];
    if (!(e & PAGE_PRESENT)) return 0;
    t = (uint64_t *)(uintptr_t)(e & PT_PHYS_MASK);
    e = t[(v >> 30) & 0x1FF];
    if (!(e & PAGE_PRESENT)) return 0;
    if (e & PAGE_4MB) return e;                 
    t = (uint64_t *)(uintptr_t)(e & PT_PHYS_MASK);
    e = t[(v >> 21) & 0x1FF];
    if (!(e & PAGE_PRESENT)) return 0;
    if (e & PAGE_4MB) return e;                 
    t = (uint64_t *)(uintptr_t)(e & PT_PHYS_MASK);
    e = t[(v >> 12) & 0x1FF];
    if (!(e & PAGE_PRESENT)) return 0;
    return e;
}

/* Return the leaf page-table entry mapping `vaddr` in the address space rooted
 * at `cr3` (raw PTE including flag bits), or 0 if not present. Read-only walk
 * by physical address; used by the ELF-loader self-test to inspect the W^X
 * bits try_elf_load produced. */
uint64_t user_lookup_pte(uint64_t cr3, uint64_t vaddr) {
    if (cr3 == 0) return 0;
    return pt_walk(cr3, vaddr);
}

/* Apply final W^X protection to an already-mapped 4 KiB user page in the
 * CURRENT task's address space: clear PAGE_WRITE unless `writable`, and set the
 * NX bit (63) unless `executable`. The ELF loader maps segments writable, copies
 * the bytes in, then calls this per page to honour the segment's p_flags so code
 * ends up read+execute and data ends up read+write+no-execute.
 *
 * Walks the page tables by physical address with a present-bit check at every
 * level (low memory is identity-mapped in the active address space during spawn,
 * exactly as create_user_pagedir relies on). No TLB shootdown is needed: the
 * target task is not yet scheduled, so its CR3 is loaded fresh when it first
 * runs. Returns 0 on success, -1 if the page is absent or not a 4 KiB leaf. */
int user_protect_page(uint64_t vaddr, int writable, int executable) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) return -1;
    uint64_t cr3 = tasks[cur].cr3;
    if (cr3 == 0) return -1;

    uint64_t *t = (uint64_t *)(uintptr_t)(cr3 & PT_PHYS_MASK);
    uint64_t e = t[(vaddr >> 39) & 0x1FF];
    if (!(e & PAGE_PRESENT)) return -1;
    t = (uint64_t *)(uintptr_t)(e & PT_PHYS_MASK);
    e = t[(vaddr >> 30) & 0x1FF];
    if (!(e & PAGE_PRESENT) || (e & PAGE_4MB)) return -1;
    t = (uint64_t *)(uintptr_t)(e & PT_PHYS_MASK);
    e = t[(vaddr >> 21) & 0x1FF];
    if (!(e & PAGE_PRESENT) || (e & PAGE_4MB)) return -1;
    t = (uint64_t *)(uintptr_t)(e & PT_PHYS_MASK);
    int i = (int)((vaddr >> 12) & 0x1FF);
    uint64_t pte = t[i];
    if (!(pte & PAGE_PRESENT)) return -1;

    if (writable)   pte |= PAGE_WRITE;
    else            pte &= ~(uint64_t)PAGE_WRITE;
    if (executable) pte &= ~PAGE_NX;
    else            pte |= PAGE_NX;

    t[i] = pte;
    return 0;
}


static int user_copy(uint64_t uaddr, uint8_t *kbuf, size_t n, int to_user, int need_write) {
    if (n == 0) return 0;
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) return -1;
    uint64_t ucr3 = tasks[cur].cr3;
    if (ucr3 == 0) return -1;
    if (!is_canonical_address(uaddr) || (uaddr + n) < uaddr) return -1;

    extern uint64_t pml4[512];
    uint64_t kcr3_phys = (uint64_t)(uintptr_t)pml4;

    uint64_t fl;
    __asm__ volatile ("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    uint64_t prev_cr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(prev_cr3));
    __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3_phys) : "memory");

    int rc = 0;
    size_t done = 0;
    uint64_t need = PAGE_PRESENT | PAGE_USER | (need_write ? (uint64_t)PAGE_WRITE : 0);
    while (done < n) {
        uint64_t v = uaddr + done;
        uint64_t e = pt_walk(ucr3, v);
        if ((e & need) != need) { rc = -1; break; }

        uint64_t phys, chunk;
        if (e & PAGE_4MB) {
            phys  = (e & 0x000FFFFFFFE00000ULL) + (v & 0x1FFFFF);
            chunk = 0x200000 - (v & 0x1FFFFF);
        } else {
            phys  = (e & PT_PHYS_MASK) + (v & 0xFFF);
            chunk = 0x1000 - (v & 0xFFF);
        }
        if (chunk > n - done) chunk = n - done;

        uint8_t *p = (uint8_t *)(uintptr_t)phys;
        if (to_user) {
            for (uint64_t i = 0; i < chunk; i++) p[i] = kbuf[done + i];
        } else {
            for (uint64_t i = 0; i < chunk; i++) kbuf[done + i] = p[i];
        }
        done += chunk;
    }

    __asm__ volatile ("mov %0, %%cr3" :: "r"(prev_cr3) : "memory");
    if (fl & 0x200) __asm__ volatile ("sti" ::: "memory");
    return rc;
}

int copy_from_user(void *dst, const void *src, size_t n) {
    if (n == 0) return 0;
    if (n > USER_MEM_MAX_COPY) n = USER_MEM_MAX_COPY;
    return user_copy((uint64_t)(uintptr_t)src, (uint8_t *)dst, n, 0, 0);
}

int copy_to_user(void *dst, const void *src, size_t n) {
    if (n == 0) return 0;
    if (n > USER_MEM_MAX_COPY) n = USER_MEM_MAX_COPY;
    return user_copy((uint64_t)(uintptr_t)dst, (uint8_t *)(void *)src, n, 1, 1);
}

void ensure_lapic_mapped(uint64_t *root_pml4) {
    extern uint64_t pml4[512];
    if (root_pml4 == NULL) root_pml4 = pml4;
    const uint64_t vaddr = 0xFEE00000ULL;
    const uint64_t paddr = 0xFEE00000ULL;
    const int pml4i = (int)((vaddr >> 39) & 511);
    const int pdpti = (int)((vaddr >> 30) & 511);
    const int pdi   = (int)((vaddr >> 21) & 511);
    const int pti   = (int)((vaddr >> 12) & 511);
    const uint64_t PS_BIT = (1ULL << 7); 

    uint64_t ent = root_pml4[pml4i];
    uint64_t *pdpt = (uint64_t *)(ent & ~0xFFFULL);
    if ((ent & PAGE_PRESENT) == 0 || !pdpt) {
        uint64_t np = alloc_user_physical_page();
        if (np == 0) return;
        pdpt = (uint64_t *)(uintptr_t)np;
        for (int k = 0; k < 512; k++) pdpt[k] = 0;
        root_pml4[pml4i] = np | PAGE_PRESENT | PAGE_WRITE;
    }

    
    ent = pdpt[pdpti];
    if (ent & PS_BIT) {
        uint64_t huge_base = ent & ~0xFFFULL & ~((1ULL<<30)-1); 
        uint64_t npd_phys = alloc_user_physical_page();
        if (npd_phys == 0) return;
        uint64_t *npd = (uint64_t *)(uintptr_t)npd_phys;
        for (int j = 0; j < 512; j++) {
            
            uint64_t base2m = huge_base + ((uint64_t)j << 21);
            npd[j] = base2m | PAGE_PRESENT | PAGE_WRITE | PS_BIT | PAGE_GLOBAL;
        }
        pdpt[pdpti] = npd_phys | PAGE_PRESENT | PAGE_WRITE; 
        ent = pdpt[pdpti];
    }

    uint64_t *pd = (uint64_t *)(ent & ~0xFFFULL);
    if ((ent & PAGE_PRESENT) == 0 || !pd) {
        uint64_t np = alloc_user_physical_page();
        if (np == 0) return;
        pd = (uint64_t *)(uintptr_t)np;
        for (int k = 0; k < 512; k++) pd[k] = 0;
        pdpt[pdpti] = np | PAGE_PRESENT | PAGE_WRITE;
    }

    
    ent = pd[pdi];
    if (ent & PS_BIT) {
        uint64_t huge_base = ent & ~0xFFFULL & ~((1ULL<<21)-1);
        uint64_t npt_phys = alloc_user_physical_page();
        if (npt_phys == 0) return;
        uint64_t *npt = (uint64_t *)(uintptr_t)npt_phys;
        for (int j = 0; j < 512; j++) {
            uint64_t base4k = huge_base + ((uint64_t)j << 12);
            uint64_t flags = PAGE_PRESENT | PAGE_WRITE | PAGE_GLOBAL;
            if (base4k == paddr) flags |= PAGE_CD; 
            npt[j] = base4k | flags;
        }
        pd[pdi] = npt_phys | PAGE_PRESENT | PAGE_WRITE; 
        ent = pd[pdi];
    }

    uint64_t *pt = (uint64_t *)(ent & ~0xFFFULL);
    if ((ent & PAGE_PRESENT) == 0 || !pt) {
        uint64_t np = alloc_user_physical_page();
        if (np == 0) return;
        pt = (uint64_t *)(uintptr_t)np;
        for (int k = 0; k < 512; k++) pt[k] = 0;
        pd[pdi] = np | PAGE_PRESENT | PAGE_WRITE;
    }

    
    pt[pti] = paddr | PAGE_PRESENT | PAGE_WRITE | PAGE_CD;

    asm volatile("invlpg (%0)" :: "r"(vaddr) : "memory");
}
