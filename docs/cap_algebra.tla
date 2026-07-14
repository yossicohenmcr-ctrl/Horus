-------------------------- MODULE cap_algebra --------------------------
(***************************************************************************)
(* Capability algebra: mint / transfer / revoke, with two REAL, machine-  *)
(* checked safety invariants.                                             *)
(*                                                                         *)
(* This replaces an earlier decorative version whose `NoEscalation` was a  *)
(* tautology (`rights <= 0xFFFFFFFF`, true for every 32-bit value) and     *)
(* whose rights masking used TLA+ boolean conjunction `/\` on numbers      *)
(* instead of bitwise AND. Here rights are modelled as SETS of right-bits, *)
(* so masking is set intersection and "no more rights than the source" is  *)
(* genuine subset (`\subseteq`) checking that TLC can falsify.             *)
(*                                                                         *)
(* Mirrors the kernel: a mint intersects the requested rights with the     *)
(* source's (rust/src/capability.rs `mint`), a transfer copies rights      *)
(* verbatim, and a revoke bumps the object's lineage generation so every   *)
(* derived capability of that object is invalidated at once (the K1/K2     *)
(* structural sweep + generation bump). `Ceiling[o]` is the authority of   *)
(* object o's primordial capability -- the most any holder may ever wield. *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Tasks,      \* set of task ids, e.g. {1, 2}
    Slots,      \* set of cnode slot ids, e.g. {1, 2, 3, 4}
    Objects,    \* set of kernel object ids, e.g. {1, 2}
    Rights,     \* the universe of right-bits, e.g. {"READ", "WRITE", "GRANT"}
    Ceiling,    \* [Objects -> SUBSET Rights]: primordial authority per object
    MaxGen      \* generation bound so the state space stays finite

ASSUME Ceiling \in [Objects -> SUBSET Rights]
ASSUME Objects \subseteq Slots     \* lets task 1 hold one primordial per object

(* Concrete ceilings for the model. TLC's .cfg parser cannot take a computed  *)
(* function literal for a constant, so the .cfg overrides the Ceiling         *)
(* constant with this operator (`Ceiling <- CeilingImpl`). Object 1's         *)
(* primordial holds every right; object 2's lacks GRANT -- so if any          *)
(* derivation of object 2 ever gained GRANT, NoEscalation would fail.         *)
CeilingImpl ==
    [o \in Objects |-> IF o = 1 THEN {"READ", "WRITE", "GRANT"}
                                 ELSE {"READ", "WRITE"}]

VARIABLES
    caps,       \* [Tasks -> [Slots -> Cap]]: the cspaces
    objgen      \* [Objects -> Nat]: current live generation of each object

vars == <<caps, objgen>>

EmptyCap == [obj |-> 0, rights |-> {}, gen |-> 0]

Cap == [obj: Objects \cup {0}, rights: SUBSET Rights, gen: 0..MaxGen]

IsLive(c) == c.obj # 0

TypeOK ==
    /\ caps \in [Tasks -> [Slots -> Cap]]
    /\ objgen \in [Objects -> 1..MaxGen]

(* Task 1 is seeded with one primordial capability per object (in the slot  *)
(* whose number equals the object id), each at that object's full ceiling   *)
(* and at generation 1. Every other slot starts empty.                      *)
Init ==
    /\ objgen = [o \in Objects |-> 1]
    /\ caps = [t \in Tasks |-> [s \in Slots |->
                 IF t = 1 /\ s \in Objects
                 THEN [obj |-> s, rights |-> Ceiling[s], gen |-> 1]
                 ELSE EmptyCap ]]

(* A capability is usable iff it is live and its generation matches the      *)
(* object's current lineage generation (a revoke bumps the generation, so a  *)
(* stale derived copy fails here -- the kernel's generation check).          *)
Valid(t, s) ==
    LET c == caps[t][s] IN
        /\ IsLive(c)
        /\ c.gen = objgen[c.obj]

(* Mint: derive a new capability at (dt, ds) from a usable source (st, ss),  *)
(* granting the requested rights INTERSECTED with the source's rights. The   *)
(* intersection is the whole point: a derived capability can never hold a    *)
(* right the source lacked. `req` ranges over every rights subset in Next.   *)
Mint(st, ss, dt, ds, req) ==
    /\ Valid(st, ss)
    /\ ~IsLive(caps[dt][ds])
    /\ LET src == caps[st][ss]
           eff == req \cap src.rights        \* masking = set intersection
       IN caps' = [caps EXCEPT ![dt][ds] =
                     [obj |-> src.obj, rights |-> eff, gen |-> src.gen]]
    /\ UNCHANGED objgen

(* Transfer is a full-rights mint: the copy carries exactly the source's     *)
(* rights (req = Rights, so eff = Rights \cap src.rights = src.rights).       *)
Transfer(st, ss, dt, ds) == Mint(st, ss, dt, ds, Rights)

(* Revoke object o: bump its generation and structurally clear every         *)
(* capability of o in every cspace. The generation bump alone would already  *)
(* invalidate them via Valid(); the sweep models the kernel's precise        *)
(* subtree clear. Crucially, capabilities of OTHER objects are untouched     *)
(* -- object-scoped revocation (the K2 exact-lineage property).              *)
Revoke(o) ==
    /\ objgen[o] < MaxGen
    /\ objgen' = [objgen EXCEPT ![o] = @ + 1]
    /\ caps' = [t \in Tasks |-> [s \in Slots |->
                 IF caps[t][s].obj = o THEN EmptyCap ELSE caps[t][s] ]]

Next ==
    \/ \E st \in Tasks, ss \in Slots, dt \in Tasks, ds \in Slots, req \in SUBSET Rights :
         Mint(st, ss, dt, ds, req)
    \/ \E st \in Tasks, ss \in Slots, dt \in Tasks, ds \in Slots :
         Transfer(st, ss, dt, ds)
    \/ \E o \in Objects : Revoke(o)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(*-------------------------------- INVARIANTS ----------------------------*)

(* REAL subset-rights / non-escalation invariant. Every live capability     *)
(* holds no more authority than its object's primordial ceiling. Because a   *)
(* mint only ever intersects rights, and a transfer copies them, rights can  *)
(* only shrink along any derivation chain -- so this must hold in every      *)
(* reachable state. Falsifiable: change `req \cap src.rights` to             *)
(* `req \cup src.rights` in Mint and TLC finds a counterexample immediately. *)
NoEscalation ==
    \A t \in Tasks, s \in Slots :
        IsLive(caps[t][s]) => caps[t][s].rights \subseteq Ceiling[caps[t][s].obj]

(* No capability carries a generation from the future: a derived copy takes  *)
(* the source generation, which is <= the object's live generation. Catches  *)
(* a revoke/mint that mismodels the lineage counter.                         *)
GenSane ==
    \A t \in Tasks, s \in Slots :
        IsLive(caps[t][s]) => caps[t][s].gen <= objgen[caps[t][s].obj]

(* Empty slots carry no rights (no authority leaks into a cleared slot).     *)
EmptyIsInert ==
    \A t \in Tasks, s \in Slots :
        ~IsLive(caps[t][s]) => caps[t][s].rights = {}

Inv == TypeOK /\ NoEscalation /\ GenSane /\ EmptyIsInert

=============================================================================
