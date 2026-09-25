theory Qubes_A
imports Main
begin

(* Moonlight Qubes isolation, Stage S0: abstract qube + policy model.
   Roadmap: docs/QUBES_ISOLATION_PLAN.md S0. Labels are nats minted by the
   (future) AdminVM; every cross-qube call carries its caller label the way
   ipc_msg_t.sender_tcb is kernel-stamped today. Policy is data: first
   matching rule wins, no match ==> Deny (fail closed). Ask suspends into a
   bounded pending queue; q_decide resolves one entry (the AdminVM confirm
   path). Audit is append-only up to max_audit (64, mirroring V2_AUDIT_MAX):
   every append is room-gated — Allow is fail-closed (state unchanged, hence
   no actuation without a record, when full), while Deny/decide/destroy
   records are best-effort (qube_audit semantics: the state change still
   applies, the record drops when full). All functions total: full queues
   fail closed,
   bad indices and unknown qubes are no-ops, never undefined.
   Anti-vacuity (V2_DESIGN Sec.6): every invariant ships with a mutant that
   violates it, and the policy theorems pin both Allow and Deny outcomes.
   Zero axioms. *)

datatype decision = Allow | Ask | Deny

(* None = wildcard (the "*" rows of the policy table). *)
record prule =
  rs :: "nat option"
  rd :: "nat option"
  rr :: nat
  rdec :: decision

record ask =
  asrc :: nat
  adst :: nat
  arpc :: nat
  ahash :: nat

record outcome =
  osrc :: nat
  odst :: nat
  orpc :: nat
  oallow :: bool

record qstate =
  qubes :: "nat list"
  policy :: "prule list"
  pending :: "ask list"
  audit :: "outcome list"

definition max_qubes :: nat where
  "max_qubes = 16"

definition max_pending :: nat where
  "max_pending = 32"

(* Audit ring cap (mirrors V2_AUDIT_MAX = 64 in kernel/qube.h). *)
definition max_audit :: nat where
  "max_audit = 64"

(* Room predicate (mirrors qube_audit_room: nonzero iff naudit < cap).
   Deny paths never consult it in C for the verdict — only the record
   append is best-effort; Allow consults it and refuses when full. *)
definition audit_room :: "qstate \<Rightarrow> bool" where
  "audit_room st = (length (audit st) < max_audit)"

definition init_qstate :: qstate where
  "init_qstate = \<lparr>qubes = [], policy = [], pending = [], audit = []\<rparr>"

(* ---- Policy lookup (executable, first match wins) ---- *)

definition match_rule :: "prule \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool" where
  "match_rule rl s d r =
   ((case rs rl of None \<Rightarrow> True | Some x \<Rightarrow> x = s) \<and>
    (case rd rl of None \<Rightarrow> True | Some x \<Rightarrow> x = d) \<and>
    rr rl = r)"

definition find_decision :: "prule list \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> decision" where
  "find_decision pol s d r =
   (case filter (\<lambda>rl. match_rule rl s d r) pol of
      [] \<Rightarrow> Deny
    | rl # _ \<Rightarrow> rdec rl)"

(* ---- Transitions (total) ---- *)

definition q_create :: "nat \<Rightarrow> qstate \<Rightarrow> qstate" where
  "q_create q st =
   (if length (qubes st) < max_qubes \<and> q \<notin> set (qubes st)
    then st\<lparr>qubes := qubes st @ [q]\<rparr> else st)"

definition q_call :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> qstate \<Rightarrow> qstate" where
  "q_call src dst rpc h st =
   (case find_decision (policy st) src dst rpc of
      Allow \<Rightarrow> (if audit_room st
                then st\<lparr>audit := audit st @
                               [\<lparr>osrc = src, odst = dst, orpc = rpc, oallow = True\<rparr>]\<rparr>
                else st)
    | Ask \<Rightarrow> (if length (pending st) < max_pending
               then st\<lparr>pending := pending st @
                              [\<lparr>asrc = src, adst = dst, arpc = rpc, ahash = h\<rparr>]\<rparr>
               else st\<lparr>audit := audit st @
                              (if audit_room st
                               then [\<lparr>osrc = src, odst = dst, orpc = rpc, oallow = False\<rparr>]
                               else [])\<rparr>)
    | Deny \<Rightarrow> st\<lparr>audit := audit st @
                        (if audit_room st
                         then [\<lparr>osrc = src, odst = dst, orpc = rpc, oallow = False\<rparr>]
                         else [])\<rparr>)"

definition pending_del :: "nat \<Rightarrow> ask list \<Rightarrow> ask list" where
  "pending_del i p = take i p @ drop (Suc i) p"

(* Decide always dequeues (mirrors qube_decide_idx: the entry is removed
   before the audit call); only the verdict record is room-gated. *)
definition q_decide :: "nat \<Rightarrow> bool \<Rightarrow> qstate \<Rightarrow> qstate" where
  "q_decide i approve st =
   (if i < length (pending st) then
      let a = pending st ! i in
      st\<lparr>pending := pending_del i (pending st),
          audit := audit st @
                   (if audit_room st
                    then [\<lparr>osrc = asrc a, odst = adst a, orpc = arpc a, oallow = approve\<rparr>]
                    else [])\<rparr>
    else st)"

(* Destroy always sweeps (mirrors qube_destroy_drop: each dropped ask is
   Deny-audited best-effort in a loop, so a full ring still records the
   fitting prefix while every matching entry is removed). *)
definition q_destroy :: "nat \<Rightarrow> qstate \<Rightarrow> qstate" where
  "q_destroy q st =
   (let dropped = filter (\<lambda>a. asrc a = q \<or> adst a = q) (pending st);
        newrecs = map (\<lambda>a. \<lparr>osrc = asrc a, odst = adst a,
                               orpc = arpc a, oallow = False\<rparr>) dropped in
    st\<lparr>qubes := filter (\<lambda>x. x \<noteq> q) (qubes st),
        pending := filter (\<lambda>a. asrc a \<noteq> q \<and> adst a \<noteq> q) (pending st),
        audit := audit st @ take (max_audit - length (audit st)) newrecs\<rparr>)"

(* ---- Invariants (real predicates, not True) ---- *)

definition q_unique :: "qstate \<Rightarrow> bool" where
  "q_unique st = distinct (qubes st)"

definition q_bounded :: "qstate \<Rightarrow> bool" where
  "q_bounded st = (length (qubes st) \<le> max_qubes)"

definition p_bounded :: "qstate \<Rightarrow> bool" where
  "p_bounded st = (length (pending st) \<le> max_pending)"

definition a_bounded :: "qstate \<Rightarrow> bool" where
  "a_bounded st = (length (audit st) \<le> max_audit)"

lemma init_invs:
  "q_unique init_qstate \<and> q_bounded init_qstate \<and> p_bounded init_qstate \<and>
   a_bounded init_qstate"
  by (simp add: init_qstate_def q_unique_def q_bounded_def p_bounded_def
                a_bounded_def max_qubes_def max_pending_def max_audit_def)

lemma pending_del_len:
  "i < length p \<Longrightarrow> length (pending_del i p) = length p - 1"
  unfolding pending_del_def by simp

(* Preservation: every transition keeps all three. *)

lemma create_unique: "q_unique st \<Longrightarrow> q_unique (q_create q st)"
  by (simp add: q_create_def q_unique_def)

lemma create_bounded: "q_bounded st \<Longrightarrow> q_bounded (q_create q st)"
  by (simp add: q_create_def q_bounded_def max_qubes_def)

lemma create_pbounded: "p_bounded st \<Longrightarrow> p_bounded (q_create q st)"
  by (simp add: q_create_def p_bounded_def)

lemma call_unique: "q_unique st \<Longrightarrow> q_unique (q_call s d r h st)"
  by (simp add: q_call_def q_unique_def split: decision.split)

lemma call_bounded: "q_bounded st \<Longrightarrow> q_bounded (q_call s d r h st)"
  by (simp add: q_call_def q_bounded_def split: decision.split)

lemma call_pbounded: "p_bounded st \<Longrightarrow> p_bounded (q_call s d r h st)"
  unfolding q_call_def p_bounded_def max_pending_def
  by (auto split: decision.split if_split)

lemma call_abounded: "a_bounded st \<Longrightarrow> a_bounded (q_call s d r h st)"
  unfolding q_call_def a_bounded_def audit_room_def max_audit_def
  by (auto split: decision.split if_split)

lemma decide_unique: "q_unique st \<Longrightarrow> q_unique (q_decide i a st)"
  by (simp add: q_decide_def q_unique_def Let_def split: if_split)

lemma decide_bounded: "q_bounded st \<Longrightarrow> q_bounded (q_decide i a st)"
  by (simp add: q_decide_def q_bounded_def Let_def split: if_split)

lemma decide_pbounded: "p_bounded st \<Longrightarrow> p_bounded (q_decide i a st)"
  unfolding q_decide_def p_bounded_def Let_def
  apply (simp split: if_split)
  apply (rule impI)
  apply (drule pending_del_len)
  apply simp
  done

lemma decide_abounded: "a_bounded st \<Longrightarrow> a_bounded (q_decide i a st)"
  unfolding q_decide_def a_bounded_def audit_room_def max_audit_def Let_def
  by (auto split: if_split)

lemma destroy_unique: "q_unique st \<Longrightarrow> q_unique (q_destroy q st)"
  unfolding q_destroy_def q_unique_def Let_def
  by (simp add: distinct_filter)

lemma destroy_bounded: "q_bounded st \<Longrightarrow> q_bounded (q_destroy q st)"
  unfolding q_destroy_def q_bounded_def Let_def
  by (simp add: order_trans[OF length_filter_le])

lemma destroy_pbounded: "p_bounded st \<Longrightarrow> p_bounded (q_destroy q st)"
  unfolding q_destroy_def p_bounded_def Let_def
  by (simp add: order_trans[OF length_filter_le])

lemma destroy_abounded: "a_bounded st \<Longrightarrow> a_bounded (q_destroy q st)"
  unfolding q_destroy_def a_bounded_def max_audit_def Let_def
  by (auto split: if_split simp: min_def)

lemma create_abounded: "a_bounded st \<Longrightarrow> a_bounded (q_create q st)"
  by (simp add: q_create_def a_bounded_def)

(* Cap preservation: all four invariants survive all four transitions. *)
lemma audit_preserved_capped:
  "\<lbrakk>q_unique st; q_bounded st; p_bounded st; a_bounded st\<rbrakk> \<Longrightarrow>
   (q_unique (q_call s d r h st) \<and> q_bounded (q_call s d r h st) \<and>
    p_bounded (q_call s d r h st) \<and> a_bounded (q_call s d r h st)) \<and>
   (q_unique (q_decide i a st) \<and> q_bounded (q_decide i a st) \<and>
    p_bounded (q_decide i a st) \<and> a_bounded (q_decide i a st)) \<and>
   (q_unique (q_destroy q st) \<and> q_bounded (q_destroy q st) \<and>
    p_bounded (q_destroy q st) \<and> a_bounded (q_destroy q st)) \<and>
   (q_unique (q_create q st) \<and> q_bounded (q_create q st) \<and>
    p_bounded (q_create q st) \<and> a_bounded (q_create q st))"
  using call_unique call_bounded call_pbounded call_abounded
        decide_unique decide_bounded decide_pbounded decide_abounded
        destroy_unique destroy_bounded destroy_pbounded destroy_abounded
        create_unique create_bounded create_pbounded create_abounded
  by metis

(* ---- Security theorems ---- *)

(* Full audit blocks Allow: fail-closed, zero state change (the broker must
   not actuate without a record — mirrors qube_audit_allow OVERFLOW). *)
lemma audit_full_blocks_allow:
  "\<lbrakk>length (audit st) \<ge> max_audit;
    find_decision (policy st) s d r = Allow\<rbrakk> \<Longrightarrow>
   q_call s d r h st = st"
  by (simp add: q_call_def audit_room_def max_audit_def)

(* Denied calls audit Deny when room remains, and never touch pending. *)
lemma call_deny_closed:
  "\<lbrakk>find_decision (policy st) s d r = Deny; audit_room st\<rbrakk> \<Longrightarrow>
   audit (q_call s d r h st) =
     audit st @ [\<lparr>osrc = s, odst = d, orpc = r, oallow = False\<rparr>] \<and>
   pending (q_call s d r h st) = pending st"
  by (simp add: q_call_def audit_room_def)

(* Deny always proceeds (verdict needs no record): pending untouched, the
   record lands iff room (mirrors qube_audit best-effort on deny paths). *)
lemma deny_appends_or_drops:
  "find_decision (policy st) s d r = Deny \<Longrightarrow>
   pending (q_call s d r h st) = pending st \<and>
   audit (q_call s d r h st) =
     audit st @ (if audit_room st
                 then [\<lparr>osrc = s, odst = d, orpc = r, oallow = False\<rparr>]
                 else [])"
  by (simp add: q_call_def)

(* Default-deny: no matching rule ==> Deny (recorded when room remains). *)
lemma call_default_deny:
  "\<lbrakk>filter (\<lambda>rl. match_rule rl s d r) (policy st) = [];
    audit_room st\<rbrakk> \<Longrightarrow>
   audit (q_call s d r h st) =
     audit st @ [\<lparr>osrc = s, odst = d, orpc = r, oallow = False\<rparr>]"
  by (simp add: q_call_def find_decision_def audit_room_def)

(* Ask suspends: audit untouched, exactly one pending entry added. *)
lemma call_ask_pending:
  "\<lbrakk>find_decision (policy st) s d r = Ask;
    length (pending st) < max_pending\<rbrakk> \<Longrightarrow>
   audit (q_call s d r h st) = audit st \<and>
   pending (q_call s d r h st) =
     pending st @ [\<lparr>asrc = s, adst = d, arpc = r, ahash = h\<rparr>]"
  by (simp add: q_call_def)

(* Ask never bypasses: a single Ask call appends no Allow entry. *)
lemma ask_no_bypass:
  "find_decision (policy st) s d r = Ask \<Longrightarrow>
   \<forall>e \<in> set (audit (q_call s d r h st)) - set (audit st). \<not> oallow e"
  unfolding q_call_def max_pending_def audit_room_def max_audit_def
  by (auto split: decision.split if_split)

(* Ask on a full pending queue denies best-effort (mirrors the
   qube_ask_enqueue overflow branch: OVERFLOW + Deny-audit, old state
   kept — the record itself drops when the ring is full). *)
lemma call_ask_full:
  "\<lbrakk>find_decision (policy st) s d r = Ask;
    \<not> length (pending st) < max_pending\<rbrakk> \<Longrightarrow>
   pending (q_call s d r h st) = pending st \<and>
   audit (q_call s d r h st) =
     audit st @ (if audit_room st
                 then [\<lparr>osrc = s, odst = d, orpc = r, oallow = False\<rparr>]
                 else [])"
  by (simp add: q_call_def)

(* Shape of every call outcome: audit unchanged, one Deny appended, or one
   rule-backed Allow appended. Pure case enumeration, feeds the two
   no-bypass/no-forge theorems below. *)
lemma q_call_audit_cases:
  "audit (q_call s d r h st) = audit st \<or>
   (\<exists>e. audit (q_call s d r h st) = audit st @ [e] \<and> \<not> oallow e) \<or>
   (audit (q_call s d r h st) =
      audit st @ [\<lparr>osrc = s, odst = d, orpc = r, oallow = True\<rparr>] \<and>
    find_decision (policy st) s d r = Allow)"
  unfolding q_call_def audit_room_def max_audit_def
  by (auto split: decision.split if_split)

(* Allow appends Allow only by rule (single-step, no forge). *)
lemma allow_only_by_rule:
  "oallow e \<Longrightarrow>
   e \<in> set (audit (q_call s d r h st)) - set (audit st) \<Longrightarrow>
   find_decision (policy st) s d r = Allow"
  using q_call_audit_cases[of s d r h st] by auto

(* Decide on a valid index resolves exactly that entry with the verdict;
   the record lands iff room (mirrors qube_decide_idx best-effort audit). *)
lemma decide_approves:
  "i < length (pending st) \<Longrightarrow>
   audit (q_decide i True st) =
     audit st @ (if audit_room st
                 then [\<lparr>osrc = asrc (pending st ! i),
                               odst = adst (pending st ! i),
                               orpc = arpc (pending st ! i), oallow = True\<rparr>]
                 else []) \<and>
   length (pending (q_decide i True st)) = length (pending st) - 1"
  unfolding q_decide_def Let_def audit_room_def
  by (simp split: if_split add: pending_del_len)

(* Decide always dequeues — deny still proceeds when the ring is full
   (the Task-1 approve-deliver full path: dequeue-as-deny, record
   best-effort, no actuation). Holds for either verdict. *)
lemma decide_always_dequeues:
  "i < length (pending st) \<Longrightarrow>
   pending (q_decide i approve st) = pending_del i (pending st)"
  by (simp add: q_decide_def Let_def split: if_split)

(* Decide on a bad index is a no-op (no silent allow). *)
lemma decide_bad_index:
  "\<not> i < length (pending st) \<Longrightarrow> q_decide i a st = st"
  by (simp add: q_decide_def)

(* Destroy records the fitting prefix of the dropped asks (mirrors the
   qube_destroy_drop loop: each Deny-audit best-effort, sweep unconditional). *)
lemma destroy_audit_capped:
  "audit (q_destroy q st) =
   audit st @ take (max_audit - length (audit st))
     (map (\<lambda>a. \<lparr>osrc = asrc a, odst = adst a,
                    orpc = arpc a, oallow = False\<rparr>)
       (filter (\<lambda>a. asrc a = q \<or> adst a = q) (pending st)))"
  by (simp add: q_destroy_def Let_def)

(* Destroying a qube denies (never allows) its in-flight asks. *)
lemma destroy_denies_inflight:
  "\<forall>e \<in> set (audit (q_destroy q st)) - set (audit st). \<not> oallow e"
proof (rule ballI)
  fix e
  assume mem: "e \<in> set (audit (q_destroy q st)) - set (audit st)"
  have e_take: "e \<in> set (take (max_audit - length (audit st))
    (map (\<lambda>a. \<lparr>osrc = asrc a, odst = adst a, orpc = arpc a, oallow = False\<rparr>)
      (filter (\<lambda>a. asrc a = q \<or> adst a = q) (pending st))))"
    using mem by (auto simp add: destroy_audit_capped)
  have e_map: "e \<in> set (map (\<lambda>a. \<lparr>osrc = asrc a, odst = adst a,
                                        orpc = arpc a, oallow = False\<rparr>)
    (filter (\<lambda>a. asrc a = q \<or> adst a = q) (pending st)))"
    using e_take by (rule in_set_takeD)
  then obtain d where
    "d \<in> set (filter (\<lambda>a. asrc a = q \<or> adst a = q) (pending st))" and
    "e = \<lparr>osrc = asrc d, odst = adst d, orpc = arpc d, oallow = False\<rparr>"
    by (auto simp: set_map)
  then show "\<not> oallow e" by simp
qed

(* ---- Mutants: each invariant CAN fail; policy CAN allow and deny ---- *)

definition mutant_dup :: qstate where
  "mutant_dup = init_qstate\<lparr>qubes := [1, 1]\<rparr>"

lemma mutant_dup_bad: "\<not> q_unique mutant_dup"
  by (simp add: mutant_dup_def q_unique_def)

definition mutant_many :: qstate where
  "mutant_many = init_qstate\<lparr>qubes := [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]\<rparr>"

lemma mutant_many_bad: "\<not> q_bounded mutant_many"
  by (simp add: mutant_many_def q_bounded_def max_qubes_def)

definition mutant_pend :: qstate where
  "mutant_pend =
   init_qstate\<lparr>pending := replicate 33 \<lparr>asrc = 1, adst = 2, arpc = 1, ahash = 0\<rparr>\<rparr>"

lemma mutant_pend_bad: "\<not> p_bounded mutant_pend"
  by (simp add: mutant_pend_def p_bounded_def max_pending_def)

(* Audit overflow witness: 65 records exceed the ring. *)
definition mutant_audit_full :: qstate where
  "mutant_audit_full =
   init_qstate\<lparr>audit := replicate 65 \<lparr>osrc = 0, odst = 0, orpc = 0, oallow = False\<rparr>\<rparr>"

lemma mutant_audit_full_bad: "\<not> a_bounded mutant_audit_full"
  by (simp add: mutant_audit_full_def a_bounded_def max_audit_def)

lemma invariants_nontrivial:
  "(\<exists>s. \<not> q_unique s) \<and> (\<exists>s. \<not> q_bounded s) \<and> (\<exists>s. \<not> p_bounded s) \<and>
   (\<exists>s. \<not> a_bounded s)"
  using mutant_dup_bad mutant_many_bad mutant_pend_bad mutant_audit_full_bad
  by blast

(* ---- Executable demo: work/vault/net policy matrix ---- *)

definition q_work :: nat where "q_work = 1"
definition q_vault :: nat where "q_vault = 2"
definition q_net :: nat where "q_net = 3"
definition rpc_sign :: nat where "rpc_sign = 1"
definition rpc_fetch :: nat where "rpc_fetch = 2"

definition demo_policy :: "prule list" where
  "demo_policy =
   [\<lparr>rs = Some q_work, rd = Some q_vault, rr = rpc_sign, rdec = Ask\<rparr>,
    \<lparr>rs = Some q_work, rd = Some q_net, rr = rpc_fetch, rdec = Allow\<rparr>]"

definition demo_init :: qstate where
  "demo_init = \<lparr>qubes = [q_work, q_vault, q_net],
                 policy = demo_policy, pending = [], audit = []\<rparr>"

value "map (\<lambda>e. (osrc e, odst e, oallow e))
         (audit (q_call q_work q_net rpc_fetch 7 demo_init))"

value "(pending (q_call q_work q_vault rpc_sign 9 demo_init),
        audit (q_call q_work q_vault rpc_sign 9 demo_init),
        audit (q_call q_vault q_net rpc_fetch 7 demo_init))"

(* Machine-checked demo values (CI-verified, not just printed). *)

lemma demo_allow_fetch:
  "audit (q_call q_work q_net rpc_fetch 7 demo_init) =
   [\<lparr>osrc = q_work, odst = q_net, orpc = rpc_fetch, oallow = True\<rparr>]"
  by eval

lemma demo_default_deny:
  "audit (q_call q_vault q_net rpc_fetch 7 demo_init) =
   [\<lparr>osrc = q_vault, odst = q_net, orpc = rpc_fetch, oallow = False\<rparr>]"
  by eval

lemma demo_ask_suspends:
  "pending (q_call q_work q_vault rpc_sign 9 demo_init) =
   [\<lparr>asrc = q_work, adst = q_vault, arpc = rpc_sign, ahash = 9\<rparr>] \<and>
   audit (q_call q_work q_vault rpc_sign 9 demo_init) = []"
  by eval

lemma demo_decide_approves:
  "audit (q_decide 0 True (q_call q_work q_vault rpc_sign 9 demo_init)) =
   [\<lparr>osrc = q_work, odst = q_vault, orpc = rpc_sign, oallow = True\<rparr>]"
  by eval

lemma demo_decide_denies:
  "audit (q_decide 0 False (q_call q_work q_vault rpc_sign 9 demo_init)) =
   [\<lparr>osrc = q_work, odst = q_vault, orpc = rpc_sign, oallow = False\<rparr>]"
  by eval

(* ---- Full-ring demo: 64-fill cap behavior (simp only — never eval
   on 64-entry states) ---- *)

(* Small lookup fact used to discharge the Allow arm by rewriting. *)
lemma demo_find_allow:
  "find_decision demo_policy q_work q_net rpc_fetch = Allow"
  by eval

lemma demo_find_deny:
  "find_decision demo_policy q_vault q_net rpc_fetch = Deny"
  by eval

(* The demo policy with a full ring: replicate 64 of one outcome. *)
definition demo_full :: qstate where
  "demo_full = demo_init\<lparr>audit :=
    replicate 64 \<lparr>osrc = q_work, odst = q_net, orpc = rpc_fetch, oallow = True\<rparr>\<rparr>"

(* Full-audit allow attempt changes nothing (fail-closed). *)
lemma demo_full_blocks_allow:
  "q_call q_work q_net rpc_fetch 7 demo_full = demo_full"
  by (simp add: demo_full_def demo_init_def demo_find_allow
                audit_room_def max_audit_def q_call_def)

(* Full-audit deny attempt keeps every entry (record dropped). *)
lemma demo_full_deny_drops:
  "audit (q_call q_vault q_net rpc_fetch 7 demo_full) = audit demo_full \<and>
   pending (q_call q_vault q_net rpc_fetch 7 demo_full) = pending demo_full"
  by (simp add: demo_full_def demo_init_def demo_find_deny
                audit_room_def max_audit_def q_call_def)

(* Full ring with one suspended ask: decide dequeues while the verdict
   record drops, preserving every existing entry. *)
definition demo_full_ask :: qstate where
  "demo_full_ask = demo_full\<lparr>pending :=
    [\<lparr>asrc = q_work, adst = q_vault, arpc = rpc_sign, ahash = 9\<rparr>]\<rparr>"

lemma demo_full_decide_drops:
  "audit (q_decide 0 True demo_full_ask) = audit demo_full_ask \<and>
   pending (q_decide 0 True demo_full_ask) = []"
  by (simp add: demo_full_ask_def demo_full_def pending_del_def
                audit_room_def max_audit_def q_decide_def Let_def)

end
