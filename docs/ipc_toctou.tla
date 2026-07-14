-------------------------- MODULE ipc_toctou --------------------------
(***************************************************************************)
(* IPC capability lookup->use TOCTOU, with a REAL, machine-checked          *)
(* no-use-after-revoke invariant.                                          *)
(*                                                                         *)
(* Models the guard on the IPC send/recv paths (src/kernel/syscall_ipc.c): *)
(* a syscall SNAPSHOTS the authorizing capability at lookup time            *)
(* (`cap_snapshot(cap_lookup(...))`), does its work, then REVALIDATES the   *)
(* slot before committing the effect (`cap_revalidate`) -- re-looking-up    *)
(* the slot and requiring the identity (object, serial, generation) to be   *)
(* byte-for-byte unchanged. A concurrent revoke NULLs the slot and a        *)
(* re-mint installs a fresh serial, so either makes revalidation fail and   *)
(* the operation abort. The property that matters: an IPC effect never      *)
(* commits using authority that was revoked (or replaced) during the        *)
(* lookup->use window.                                                      *)
(*                                                                         *)
(* Mirrors the kernel: `cap_snapshot` captures (serial, generation, object, *)
(* valid); `cap_revalidate` re-looks-up and returns NULL unless the current *)
(* cap matches that snapshot exactly (a revoke nulls it, a re-mint bumps    *)
(* the serial, a lineage revoke bumps the generation). The IPC handlers     *)
(* bail out (`return -1`) when revalidation fails.                          *)
(*                                                                         *)
(* Falsifiable: let Commit fire without the revalidate guard (set           *)
(* USE_REVALIDATE_GUARD = FALSE in the .cfg) and TLC finds a sender that    *)
(* commits an effect after its authority was revoked.                       *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Senders,               \* set of concurrent IPC callers, e.g. {1, 2}
    MaxSerial,             \* bound on re-mint serials so the space is finite
    USE_REVALIDATE_GUARD   \* TRUE = model the kernel; FALSE = falsify the guard

ASSUME MaxSerial \in Nat
ASSUME USE_REVALIDATE_GUARD \in BOOLEAN

(* The one authorizing capability slot the senders look up (slot 3 in the   *)
(* kernel: the IPC endpoint cap). `serial` is the fresh-per-mint identity,   *)
(* `valid` is FALSE once revoked/nulled. `object`/`generation` fold into     *)
(* `serial` here: any revoke or re-mint changes at least the serial, which   *)
(* is exactly what cap_revalidate keys on.                                  *)
VARIABLES
    slotValid,      \* BOOLEAN: is the slot currently a live capability?
    slotSerial,     \* Nat: the current cap's fresh-mint serial (0 when empty)
    sstate,         \* [Senders -> {"idle","snapped","done"}]
    snapValid,      \* [Senders -> BOOLEAN]: snapshot's validity
    snapSerial,     \* [Senders -> Nat]: snapshot's serial
    committed,      \* [Senders -> BOOLEAN]: did this sender commit its IPC effect?
    usedLiveAuth    \* [Senders -> BOOLEAN]: was the authority live+matching at commit?

vars == <<slotValid, slotSerial, sstate, snapValid, snapSerial,
          committed, usedLiveAuth>>

Serials == 0..MaxSerial

TypeOK ==
    /\ slotValid \in BOOLEAN
    /\ slotSerial \in Serials
    /\ sstate \in [Senders -> {"idle", "snapped", "done"}]
    /\ snapValid \in [Senders -> BOOLEAN]
    /\ snapSerial \in [Senders -> Serials]
    /\ committed \in [Senders -> BOOLEAN]
    /\ usedLiveAuth \in [Senders -> BOOLEAN]

Init ==
    /\ slotValid = TRUE
    /\ slotSerial = 1
    /\ sstate = [c \in Senders |-> "idle"]
    /\ snapValid = [c \in Senders |-> FALSE]
    /\ snapSerial = [c \in Senders |-> 0]
    /\ committed = [c \in Senders |-> FALSE]
    /\ usedLiveAuth = [c \in Senders |-> FALSE]

(*----------------------------- ADVERSARY (revoke / re-mint) -------------*)

(* Revoke the slot: null it. Models revoke_subtree clearing the capability;  *)
(* cap_lookup then returns NULL, so cap_revalidate fails. *)
Revoke ==
    /\ slotValid = TRUE
    /\ slotValid' = FALSE
    /\ slotSerial' = 0
    /\ UNCHANGED <<sstate, snapValid, snapSerial, committed, usedLiveAuth>>

(* Re-mint into the slot with a FRESH serial. Models the slot being reused   *)
(* by a new capability; the serial necessarily differs, so a stale snapshot  *)
(* fails revalidation even though the slot is live again.                    *)
Remint ==
    /\ slotValid = FALSE
    /\ slotSerial < MaxSerial
    /\ slotValid' = TRUE
    /\ slotSerial' = slotSerial + 1
    /\ UNCHANGED <<sstate, snapValid, snapSerial, committed, usedLiveAuth>>

(*----------------------------- IPC SENDER -------------------------------*)

(* Lookup + snapshot the authorizing capability (cap_snapshot(cap_lookup)).  *)
(* A lookup of a nulled slot snapshots valid=FALSE (the handler would bail    *)
(* immediately; we still let it proceed to show revalidate also catches it). *)
Snapshot(c) ==
    /\ sstate[c] = "idle"
    /\ snapValid' = [snapValid EXCEPT ![c] = slotValid]
    /\ snapSerial' = [snapSerial EXCEPT ![c] = slotSerial]
    /\ sstate' = [sstate EXCEPT ![c] = "snapped"]
    /\ UNCHANGED <<slotValid, slotSerial, committed, usedLiveAuth>>

(* Revalidate + commit the IPC effect. `live` is the real cap_revalidate      *)
(* result computed against the CURRENT slot: the snapshot was valid AND the   *)
(* slot is still live with the same serial. With the guard (the kernel), the  *)
(* effect commits only when `live`; without it (falsification), the effect    *)
(* commits regardless and records that it used dead authority.                *)
Commit(c) ==
    /\ sstate[c] = "snapped"
    /\ LET live == snapValid[c] /\ slotValid /\ (slotSerial = snapSerial[c])
       IN /\ (USE_REVALIDATE_GUARD => live)      \* kernel bails when ~live
          /\ committed' = [committed EXCEPT ![c] = TRUE]
          /\ usedLiveAuth' = [usedLiveAuth EXCEPT ![c] = live]
    /\ sstate' = [sstate EXCEPT ![c] = "done"]
    /\ UNCHANGED <<slotValid, slotSerial, snapValid, snapSerial>>

(* A sender whose revalidation fails aborts (the kernel `return -1`). Only    *)
(* enabled under the guard; it clears the way without committing.             *)
Abort(c) ==
    /\ USE_REVALIDATE_GUARD
    /\ sstate[c] = "snapped"
    /\ ~(snapValid[c] /\ slotValid /\ (slotSerial = snapSerial[c]))
    /\ sstate' = [sstate EXCEPT ![c] = "done"]
    /\ UNCHANGED <<slotValid, slotSerial, snapValid, snapSerial, committed, usedLiveAuth>>

Next ==
    \/ Revoke
    \/ Remint
    \/ \E c \in Senders : Snapshot(c)
    \/ \E c \in Senders : Commit(c)
    \/ \E c \in Senders : Abort(c)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(*-------------------------------- INVARIANTS ----------------------------*)

(* REAL no-use-after-revoke invariant: every committed IPC effect used        *)
(* authority that was live and identity-matched at the instant it committed.  *)
(* The snapshot/revalidate guard is exactly what makes this hold; dropping it *)
(* (USE_REVALIDATE_GUARD = FALSE) lets a Commit fire right after a Revoke and  *)
(* TLC reports a committed sender with usedLiveAuth = FALSE.                   *)
NoUseAfterRevoke ==
    \A c \in Senders : committed[c] => usedLiveAuth[c]

Inv == TypeOK /\ NoUseAfterRevoke

=============================================================================
