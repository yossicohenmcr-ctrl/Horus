-------------------------- MODULE cap_seqlock --------------------------
(***************************************************************************)
(* Two-CPU seqlock for lock-free capability reads, with a REAL,            *)
(* machine-checked consistency invariant.                                  *)
(*                                                                         *)
(* This models audit finding 3.1's fix: `cap_lookup` is a lock-free reader *)
(* over a version counter (`cap_seq`) that a writer bumps ODD on acquiring *)
(* `cap_lock` and EVEN on releasing it, while mint / transfer / revoke /   *)
(* grant mutate a `capability_t` under that lock on another CPU. The       *)
(* property that matters: a reader that COMMITS a snapshot (it saw an even *)
(* counter and the same counter value before and after reading the fields) *)
(* never observes a TORN capability -- e.g. new rights paired with an old  *)
(* serial, or a half-nulled slot -- even though the two fields are read     *)
(* non-atomically and a writer can interleave its two non-atomic stores    *)
(* between them.                                                           *)
(*                                                                         *)
(* Mirrors the kernel (src/kernel/scheduler.c + src/kernel/capability.c):  *)
(*   - the protected object has two fields written as a matched pair; here  *)
(*     `mem.a` and `mem.b` stand in for (rights, serial). A consistent      *)
(*     capability always has a = b; a torn read is exactly a # b.           *)
(*   - a writer holds `cap_lock` (modelled by `lockOwner`), so writers are  *)
(*     serialised; the seqlock bump is intrinsic to holding the lock        *)
(*     (odd on acquire, even on release), matching the spin_lock/spin_unlock*)
(*     cap_seq bump that no future writer can forget.                       *)
(*   - the lock HOLDER reads via `cap_lookup_locked` (no seqlock), so the   *)
(*     lock-free reader path modelled here only runs on a CPU NOT holding   *)
(*     the lock.                                                            *)
(*                                                                         *)
(* Falsifiable: weaken CommitRead to commit regardless of the s1 = s2       *)
(* check (or make the writer bump `seq` only once instead of on both        *)
(* acquire and release) and TLC finds a committed snapshot with a # b.      *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    CPUs,        \* set of CPU ids, e.g. {1, 2}
    MaxWrites    \* bound on completed writes so the state space stays finite

ASSUME MaxWrites \in Nat

VARIABLES
    mem,        \* [a: Nat, b: Nat]: the two halves of the protected capability
    seq,        \* Nat: the cap_seq counter (even = stable, odd = write in flight)
    lockOwner,  \* CPU holding cap_lock, or 0 if free
    wphase,     \* 0 idle, 1 acquired, 2 wrote a, 3 wrote b (ready to release)
    wtarget,    \* the value being written into both halves in this critical section
    writes,     \* Nat: number of completed writes (bounds the run)
    rstate,     \* [CPUs -> {"idle","got_s1","got_a","got_b"}]: reader progress
    rs1,        \* [CPUs -> Nat]: the seq value the reader sampled first
    ra,         \* [CPUs -> Nat]: the value the reader read from mem.a
    rb,         \* [CPUs -> Nat]: the value the reader read from mem.b
    snap,       \* [CPUs -> [a: Nat, b: Nat]]: the reader's last COMMITTED snapshot
    snapValid   \* [CPUs -> BOOLEAN]: whether snap holds a committed read

vars == <<mem, seq, lockOwner, wphase, wtarget, writes,
          rstate, rs1, ra, rb, snap, snapValid>>

Vals == 0..MaxWrites

TypeOK ==
    /\ mem \in [a: Vals, b: Vals]
    /\ seq \in 0..(2 * MaxWrites)
    /\ lockOwner \in CPUs \cup {0}
    /\ wphase \in 0..3
    /\ wtarget \in Vals
    /\ writes \in 0..MaxWrites
    /\ rstate \in [CPUs -> {"idle", "got_s1", "got_a", "got_b"}]
    /\ rs1 \in [CPUs -> 0..(2 * MaxWrites)]
    /\ ra \in [CPUs -> Vals]
    /\ rb \in [CPUs -> Vals]
    /\ snap \in [CPUs -> [a: Vals, b: Vals]]
    /\ snapValid \in [CPUs -> BOOLEAN]

Init ==
    /\ mem = [a |-> 0, b |-> 0]
    /\ seq = 0
    /\ lockOwner = 0
    /\ wphase = 0
    /\ wtarget = 0
    /\ writes = 0
    /\ rstate = [c \in CPUs |-> "idle"]
    /\ rs1 = [c \in CPUs |-> 0]
    /\ ra = [c \in CPUs |-> 0]
    /\ rb = [c \in CPUs |-> 0]
    /\ snap = [c \in CPUs |-> [a |-> 0, b |-> 0]]
    /\ snapValid = [c \in CPUs |-> FALSE]

(*----------------------------- WRITER (cap_lock holder) -----------------*)

(* spin_lock(&cap_lock): take the free lock and bump cap_seq ODD (the bump  *)
(* happens after the acquire barrier, so it is intrinsic to holding the     *)
(* lock). Only an idle CPU -- one not in the middle of a lock-free read --   *)
(* may acquire, mirroring that a CPU either reads or writes, not both.       *)
Acquire(c) ==
    /\ lockOwner = 0
    /\ wphase = 0
    /\ writes < MaxWrites
    /\ rstate[c] = "idle"
    /\ lockOwner' = c
    /\ seq' = seq + 1
    /\ wtarget' = writes + 1
    /\ wphase' = 1
    /\ UNCHANGED <<mem, writes, rstate, rs1, ra, rb, snap, snapValid>>

(* Store the first half. Between here and WriteB the object is TORN         *)
(* (mem.a is the new version, mem.b still the old one) -- this is the        *)
(* window a naive lock-free reader could observe.                           *)
WriteA(c) ==
    /\ lockOwner = c
    /\ wphase = 1
    /\ mem' = [mem EXCEPT !.a = wtarget]
    /\ wphase' = 2
    /\ UNCHANGED <<seq, lockOwner, wtarget, writes, rstate, rs1, ra, rb, snap, snapValid>>

(* Store the second half; the object is a matched pair again. *)
WriteB(c) ==
    /\ lockOwner = c
    /\ wphase = 2
    /\ mem' = [mem EXCEPT !.b = wtarget]
    /\ wphase' = 3
    /\ UNCHANGED <<seq, lockOwner, wtarget, writes, rstate, rs1, ra, rb, snap, snapValid>>

(* spin_unlock(&cap_lock): bump cap_seq EVEN (before the release barrier)    *)
(* and drop the lock. The counter is now higher than any reader that started *)
(* before this critical section sampled, so such a reader's s1 = s2 check    *)
(* fails and it retries.                                                     *)
Release(c) ==
    /\ lockOwner = c
    /\ wphase = 3
    /\ seq' = seq + 1
    /\ lockOwner' = 0
    /\ wphase' = 0
    /\ wtarget' = 0
    /\ writes' = writes + 1
    /\ UNCHANGED <<mem, rstate, rs1, ra, rb, snap, snapValid>>

(*----------------------------- LOCK-FREE READER (cap_lookup) ------------*)

(* s1 = load(cap_seq). Only a CPU that does NOT hold cap_lock takes this     *)
(* path (the holder uses cap_lookup_locked instead).                        *)
ReadSeq1(c) ==
    /\ lockOwner # c
    /\ rstate[c] = "idle"
    /\ rs1' = [rs1 EXCEPT ![c] = seq]
    /\ rstate' = [rstate EXCEPT ![c] = "got_s1"]
    /\ UNCHANGED <<mem, seq, lockOwner, wphase, wtarget, writes, ra, rb, snap, snapValid>>

(* if (s1 & 1) pause; continue;  -- an odd sample means a write is in flight, *)
(* so the reader restarts WITHOUT reading the fields.                         *)
SpinOdd(c) ==
    /\ rstate[c] = "got_s1"
    /\ rs1[c] % 2 = 1
    /\ rstate' = [rstate EXCEPT ![c] = "idle"]
    /\ UNCHANGED <<mem, seq, lockOwner, wphase, wtarget, writes, rs1, ra, rb, snap, snapValid>>

(* Even sample: read the first field. A writer may interleave its stores     *)
(* after this point -- that is the whole point of the seqlock.               *)
ReadA(c) ==
    /\ rstate[c] = "got_s1"
    /\ rs1[c] % 2 = 0
    /\ ra' = [ra EXCEPT ![c] = mem.a]
    /\ rstate' = [rstate EXCEPT ![c] = "got_a"]
    /\ UNCHANGED <<mem, seq, lockOwner, wphase, wtarget, writes, rs1, rb, snap, snapValid>>

ReadB(c) ==
    /\ rstate[c] = "got_a"
    /\ rb' = [rb EXCEPT ![c] = mem.b]
    /\ rstate' = [rstate EXCEPT ![c] = "got_b"]
    /\ UNCHANGED <<mem, seq, lockOwner, wphase, wtarget, writes, rs1, ra, snap, snapValid>>

(* s2 = load(cap_seq); if (s1 == s2) return snapshot; else retry.            *)
(* Commit only when the counter is unchanged (hence even throughout and no   *)
(* write completed in the window). Otherwise discard and restart.            *)
CommitRead(c) ==
    /\ rstate[c] = "got_b"
    /\ rstate' = [rstate EXCEPT ![c] = "idle"]
    /\ IF seq = rs1[c]
         THEN /\ snap' = [snap EXCEPT ![c] = [a |-> ra[c], b |-> rb[c]]]
              /\ snapValid' = [snapValid EXCEPT ![c] = TRUE]
         ELSE /\ UNCHANGED <<snap, snapValid>>
    /\ UNCHANGED <<mem, seq, lockOwner, wphase, wtarget, writes, rs1, ra, rb>>

Next ==
    \/ \E c \in CPUs : Acquire(c)
    \/ \E c \in CPUs : WriteA(c)
    \/ \E c \in CPUs : WriteB(c)
    \/ \E c \in CPUs : Release(c)
    \/ \E c \in CPUs : ReadSeq1(c)
    \/ \E c \in CPUs : SpinOdd(c)
    \/ \E c \in CPUs : ReadA(c)
    \/ \E c \in CPUs : ReadB(c)
    \/ \E c \in CPUs : CommitRead(c)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(*-------------------------------- INVARIANTS ----------------------------*)

(* REAL consistency invariant: every COMMITTED lock-free read is a matched   *)
(* pair -- it never pairs a half from one version with a half from another.  *)
(* Because the writer always sets both halves to the same value, a torn read *)
(* is exactly `a # b`; the seqlock's s1 = s2 gate is what must exclude it.   *)
(* Weaken CommitRead to commit unconditionally and TLC produces a            *)
(* counterexample where the reader latched mem.a from a new write and mem.b  *)
(* from before it.                                                           *)
NoTornRead ==
    \A c \in CPUs : snapValid[c] => snap[c].a = snap[c].b

(* At most one CPU holds cap_lock at any time (writers are serialised), so   *)
(* the two non-atomic stores never race another writer's stores.            *)
MutualExclusion ==
    \A c1 \in CPUs, c2 \in CPUs :
        (lockOwner = c1 /\ lockOwner = c2) => c1 = c2

(* The counter's parity tracks the lock: odd exactly while the lock is held  *)
(* (a write is in flight), even exactly while it is free. This is the        *)
(* structural property a lock-free reader relies on to detect a live write.  *)
ParityTracksLock ==
    /\ (lockOwner # 0) => (seq % 2 = 1)
    /\ (lockOwner = 0) => (seq % 2 = 0)

Inv == TypeOK /\ NoTornRead /\ MutualExclusion /\ ParityTracksLock

=============================================================================
