-------------------------- MODULE sched_smp --------------------------
(***************************************************************************)
(* SMP run-pool task dispatch, with a REAL, machine-checked no-double-run   *)
(* invariant.                                                              *)
(*                                                                         *)
(* Models the multi-CPU scheduler (src/kernel/scheduler.c): every CPU pulls *)
(* runnable tasks from a single shared pool under `sched_raw_lock`, and     *)
(* claims a task by setting `task_running_cpu[t]` -- only ever picking a     *)
(* candidate whose `task_running_cpu[t] < 0` (unclaimed). The property that  *)
(* matters: no task is ever running on two CPUs at once. The lock is what    *)
(* makes the observe-candidate-then-claim sequence atomic; without it two    *)
(* CPUs can both observe the same unclaimed task and both claim it.          *)
(*                                                                         *)
(* Mirrors the kernel: `running[cpu]` is the task executing on a CPU         *)
(* (percpu_current_task), `claimedBy[t]` is task_running_cpu (0 = the        *)
(* kernel's -1 "unclaimed"), and the pick runs inside sched_raw_lock /       *)
(* sched_raw_unlock. The outgoing task is released (claimedBy := 0) as the    *)
(* CPU takes the new one, all under the lock.                               *)
(*                                                                         *)
(* Falsifiable: set USE_LOCK = FALSE in the .cfg (drop mutual exclusion on   *)
(* the pick) and TLC finds two CPUs running the same task (NoDoubleRun       *)
(* fails), and the claim table disagreeing with who is running it            *)
(* (ClaimConsistent fails).                                                 *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    CPUs,       \* set of CPU ids, e.g. {1, 2}
    Tasks,      \* set of runnable task ids, e.g. {1, 2}
    USE_LOCK    \* TRUE = model sched_raw_lock; FALSE = falsify (no mutex)

ASSUME USE_LOCK \in BOOLEAN

VARIABLES
    running,    \* [CPUs -> Tasks \cup {0}]: task currently on each CPU (0 = idle)
    claimedBy,  \* [Tasks -> CPUs \cup {0}]: task_running_cpu (0 = unclaimed)
    lock,       \* CPUs \cup {0}: sched_raw_lock holder (0 = free)
    phase,      \* [CPUs -> {"idle","holding","observed"}]: pick progress
    cand        \* [CPUs -> Tasks \cup {0}]: candidate a CPU has observed

vars == <<running, claimedBy, lock, phase, cand>>

TypeOK ==
    /\ running \in [CPUs -> Tasks \cup {0}]
    /\ claimedBy \in [Tasks -> CPUs \cup {0}]
    /\ lock \in CPUs \cup {0}
    /\ phase \in [CPUs -> {"idle", "holding", "observed"}]
    /\ cand \in [CPUs -> Tasks \cup {0}]

Init ==
    /\ running = [c \in CPUs |-> 0]
    /\ claimedBy = [t \in Tasks |-> 0]
    /\ lock = 0
    /\ phase = [c \in CPUs |-> "idle"]
    /\ cand = [c \in CPUs |-> 0]

(* sched_raw_lock(): begin a pick. Under the real lock only one CPU may hold  *)
(* it, so only one CPU runs observe->claim at a time. With USE_LOCK = FALSE    *)
(* the mutual-exclusion guard is dropped and CPUs pick concurrently.          *)
Acquire(c) ==
    /\ phase[c] = "idle"
    /\ (USE_LOCK => lock = 0)
    /\ lock' = (IF USE_LOCK THEN c ELSE lock)
    /\ phase' = [phase EXCEPT ![c] = "holding"]
    /\ UNCHANGED <<running, claimedBy, cand>>

(* Scan the shared pool: observe a runnable task not currently claimed        *)
(* (task_running_cpu[t] < 0). Records the candidate; the claim is a separate  *)
(* step, so without the lock a second CPU can observe the same task here.     *)
Observe(c, t) ==
    /\ phase[c] = "holding"
    /\ claimedBy[t] = 0
    /\ cand' = [cand EXCEPT ![c] = t]
    /\ phase' = [phase EXCEPT ![c] = "observed"]
    /\ UNCHANGED <<running, claimedBy, lock>>

(* Claim the observed candidate: release the CPU's outgoing task and take the *)
(* new one (claimedBy := cpu), then release the lock. Under the lock this is   *)
(* atomic with Observe; without it two CPUs can reach here on the same task.   *)
Commit(c) ==
    /\ phase[c] = "observed"
    /\ LET t == cand[c]
           old == running[c]
       IN /\ claimedBy' = [tt \in Tasks |->
                             IF tt = t THEN c
                             ELSE IF tt = old THEN 0
                             ELSE claimedBy[tt]]
          /\ running' = [running EXCEPT ![c] = t]
    /\ lock' = (IF USE_LOCK THEN 0 ELSE lock)
    /\ phase' = [phase EXCEPT ![c] = "idle"]
    /\ cand' = [cand EXCEPT ![c] = 0]

(* A running task voluntarily yields / is preempted: the CPU drops it back to  *)
(* the pool (claimedBy := 0) and goes idle. Keeps the pool cyclic and lets a   *)
(* task be re-picked, exercising that reuse never double-runs.                 *)
Yield(c) ==
    /\ phase[c] = "idle"
    /\ running[c] # 0
    /\ LET old == running[c]
       IN /\ claimedBy' = [claimedBy EXCEPT ![old] = 0]
          /\ running' = [running EXCEPT ![c] = 0]
    /\ UNCHANGED <<lock, phase, cand>>

Next ==
    \/ \E c \in CPUs : Acquire(c)
    \/ \E c \in CPUs, t \in Tasks : Observe(c, t)
    \/ \E c \in CPUs : Commit(c)
    \/ \E c \in CPUs : Yield(c)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(*-------------------------------- INVARIANTS ----------------------------*)

(* REAL no-double-run invariant: a task never executes on two CPUs at once.   *)
(* The sched_raw_lock mutual exclusion over observe+claim is what guarantees  *)
(* it; USE_LOCK = FALSE lets two CPUs claim the same task and TLC exhibits a  *)
(* state with running[c1] = running[c2] # 0, c1 # c2.                         *)
NoDoubleRun ==
    \A c1 \in CPUs, c2 \in CPUs :
        (running[c1] # 0 /\ running[c1] = running[c2]) => c1 = c2

(* The run-state and the claim table agree: a task is claimed by exactly the  *)
(* CPU running it, and an unclaimed task runs nowhere. Catches updating one    *)
(* structure but not the other (task_running_cpu vs percpu_current_task).     *)
ClaimConsistent ==
    /\ \A c \in CPUs : running[c] # 0 => claimedBy[running[c]] = c
    /\ \A t \in Tasks : claimedBy[t] # 0 => running[claimedBy[t]] = t

Inv == TypeOK /\ NoDoubleRun /\ ClaimConsistent

=============================================================================
