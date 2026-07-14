------------------------ MODULE paging_isolation ------------------------
(***************************************************************************)
(* Per-task address-space isolation, with a REAL machine-checked          *)
(* isolation invariant.                                                    *)
(*                                                                         *)
(* This replaces an earlier version that kept a single GLOBAL page-table   *)
(* array indexed by `(vaddr / PAGE) % 1024` -- shared across all tasks, so *)
(* it could not even express isolation (two tasks mapping the same virtual *)
(* page aliased the same model cell). Here every task has its OWN mapping  *)
(* (`map[t]`), and a physical user frame has at most one owner, so the     *)
(* model can state and check the property that matters: no user frame is   *)
(* ever mapped into two different tasks, and no user mapping reaches a      *)
(* kernel frame.                                                           *)
(*                                                                         *)
(* Mirrors the kernel: each task gets a private PML4 / page-table tree     *)
(* (scheduler.c per-task cr3), the page allocator hands each frame to one  *)
(* task (rust/src/memory.rs refcount table), and user PTEs may only map    *)
(* user-range frames with the U bit -- the kernel half is never user-      *)
(* accessible.                                                             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Tasks,          \* set of task ids, e.g. {1, 2}
    UserPages,      \* user virtual page numbers a task may map, e.g. {0, 1}
    UserFrames,     \* physical frames the user allocator owns, e.g. {1, 2, 3}
    KernelFrames    \* physical frames reserved for the kernel, e.g. {90, 91}

ASSUME UserFrames \cap KernelFrames = {}   \* disjoint physical pools

VARIABLES
    map,        \* [Tasks -> [UserPages -> Frames \cup {0}]]: per-task user mappings (0 = unmapped)
    owner       \* [UserFrames -> Tasks \cup {0}]: which task holds each user frame (0 = free)

vars == <<map, owner>>

AllFrames == UserFrames \cup KernelFrames

TypeOK ==
    /\ map \in [Tasks -> [UserPages -> AllFrames \cup {0}]]
    /\ owner \in [UserFrames -> Tasks \cup {0}]

Init ==
    /\ map = [t \in Tasks |-> [p \in UserPages |-> 0]]
    /\ owner = [f \in UserFrames |-> 0]

(* Map user page `p` of task `t` to a currently-free user frame `f`. The     *)
(* allocator hands out only frames it owns and only if unowned, so the frame *)
(* becomes exclusively `t`'s. A page already mapped is left alone (the fault *)
(* handler is idempotent). This is the demand-paging / COW allocation path.  *)
MapUserPage(t, p, f) ==
    /\ f \in UserFrames
    /\ owner[f] = 0                 \* frame is free -> exclusive ownership
    /\ map[t][p] = 0                \* page not already mapped
    /\ map' = [map EXCEPT ![t][p] = f]
    /\ owner' = [owner EXCEPT ![f] = t]

(* Unmap: a task drops one of its pages and the frame returns to the free    *)
(* pool (task teardown / munmap). Keeps the state space cyclic and finite    *)
(* and lets frames be reused -- exercising that reuse never aliases owners.  *)
UnmapUserPage(t, p) ==
    /\ map[t][p] # 0
    /\ map[t][p] \in UserFrames
    /\ owner' = [owner EXCEPT ![map[t][p]] = 0]
    /\ map' = [map EXCEPT ![t][p] = 0]

Next ==
    \/ \E t \in Tasks, p \in UserPages, f \in UserFrames : MapUserPage(t, p, f)
    \/ \E t \in Tasks, p \in UserPages : UnmapUserPage(t, p)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(*-------------------------------- INVARIANTS ----------------------------*)

(* REAL per-task isolation invariant. No physical user frame is mapped into  *)
(* two distinct tasks at once. Falsifiable: drop the `owner[f] = 0` guard    *)
(* from MapUserPage and TLC finds two tasks sharing a frame.                 *)
NoSharedFrame ==
    \A t1 \in Tasks, t2 \in Tasks, p1 \in UserPages, p2 \in UserPages :
        (t1 # t2 /\ map[t1][p1] # 0 /\ map[t2][p2] # 0)
            => map[t1][p1] # map[t2][p2]

(* A user mapping never reaches a kernel-reserved frame (no ring-3 window     *)
(* into kernel memory). Falsifiable: let MapUserPage pick from KernelFrames.  *)
NoKernelMapping ==
    \A t \in Tasks, p \in UserPages :
        map[t][p] # 0 => map[t][p] \in UserFrames

(* The ownership table and the mappings agree: if a task maps a user frame,   *)
(* that frame is recorded as owned by exactly that task. Catches an allocator *)
(* that updates one structure but not the other (a use-after-free / double-   *)
(* allocation bug in the refcount table).                                     *)
OwnerConsistent ==
    \A t \in Tasks, p \in UserPages :
        (map[t][p] \in UserFrames) => owner[map[t][p]] = t

Inv == TypeOK /\ NoSharedFrame /\ NoKernelMapping /\ OwnerConsistent

=============================================================================
