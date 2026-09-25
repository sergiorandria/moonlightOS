theory Qubes_B
imports Qubes_A
begin

(* Moonlight Qubes S1/S2: label confinement + C refinement over Qubes_A.
   This theory formalizes kernel/qube.h in HOL and ties it to the abstract
   model: qlabel is the qube_of[tid] table, raw_ok mirrors qube_raw_ok
   (same label always rendezvous; cross-label needs the QX grant),
   c_decide mirrors the qube_decide first-match-wins loop, c_q_call mirrors
   the qube_decide + qube_ask_enqueue call path (including the full-queue
   fail-closed branch), and c_q_destroy mirrors the qube_destroy_drop
   read/write sweep. Refinement relation: the C build clamps qubes to 9
   (c_max_qubes) while the spec allows 16 (max_qubes), so every C-bounded
   state is spec-bounded but not vice versa (mutant_b_c9 witnesses the
   strictness); the pending bound (32) coincides. Audit is append-only up to
   max_audit (64) in both levels: the C operators below take the same room
   gating as Qubes_A arm-for-arm (Allow fail-closed, all other records
   best-effort). All functions total. Zero axioms. *)

(* ---- Raw rendezvous gate (mirrors qube_raw_ok) ---- *)

(* Labels: qube_of[tid] as a total function. has_qx is the QX grant bit. *)
definition raw_ok :: "(nat \<Rightarrow> nat) \<Rightarrow> bool \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool" where
  "raw_ok L has_qx s d = (if L s = L d then True else has_qx)"

(* Same label always rendezvous, grant irrelevant. *)
lemma raw_ok_same:
  "L s = L d \<Longrightarrow> raw_ok L has_qx s d"
  by (simp add: raw_ok_def)

(* Cross-label rendezvous exactly when the grant is present. *)
lemma raw_ok_cross:
  "L s \<noteq> L d \<Longrightarrow> raw_ok L has_qx s d = has_qx"
  by (simp add: raw_ok_def)

(* Both outcomes pinned by evaluation. *)
lemma raw_ok_allow_same:
  "raw_ok (\<lambda>_. 0) True 3 5"
  by eval

lemma raw_ok_deny_cross:
  "\<not> raw_ok id False 1 2"
  by eval

(* Mutant: cross-qube rendezvous without a grant is rejected. *)
definition mutant_forge_src :: nat where
  "mutant_forge_src = 0"

definition mutant_forge_L :: "nat \<Rightarrow> nat" where
  "mutant_forge_L = (\<lambda>n. if n = 0 then 1 else 2)"

lemma mutant_forge_bad:
  "\<not> raw_ok mutant_forge_L False mutant_forge_src 1"
  by (simp add: mutant_forge_L_def mutant_forge_src_def raw_ok_def)

(* ---- C bounds and the refinement relation ---- *)

(* C build clamps (kernel/qube.h): qubes to 9, policy/pending to 32.
   Spec (Qubes_A): qubes to 16, pending to 32. *)
definition c_max_qubes :: nat where
  "c_max_qubes = 9"

definition c_max_policy :: nat where
  "c_max_policy = 32"

definition c_max_pending :: nat where
  "c_max_pending = 32"

definition c_qbounded :: "qstate \<Rightarrow> bool" where
  "c_qbounded st = (length (qubes st) \<le> c_max_qubes)"

definition c_policy_bounded :: "qstate \<Rightarrow> bool" where
  "c_policy_bounded st = (length (policy st) \<le> c_max_policy)"

definition c_pbounded :: "qstate \<Rightarrow> bool" where
  "c_pbounded st = (length (pending st) \<le> c_max_pending)"

(* C qube bound implies the spec bound (9 \<le> 16). *)
lemma c_qubes_implies_spec:
  "c_qbounded st \<Longrightarrow> q_bounded st"
  unfolding c_qbounded_def q_bounded_def c_max_qubes_def max_qubes_def
  by arith

(* Pending bound coincides (both 32). *)
lemma c_pbounded_iff:
  "c_pbounded st = p_bounded st"
  by (simp add: c_pbounded_def p_bounded_def c_max_pending_def max_pending_def)

(* ---- C policy loop (mirrors qube_decide) ---- *)

fun c_decide :: "prule list \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> decision" where
  "c_decide [] s d r = Deny" |
  "c_decide (rl # rest) s d r =
    (if match_rule rl s d r then rdec rl else c_decide rest s d r)"

lemma find_cons:
  "find_decision (rl # rest) s d r =
   (if match_rule rl s d r then rdec rl else find_decision rest s d r)"
  unfolding find_decision_def
  by (simp split: list.split)

(* The C loop returns exactly the spec lookup. *)
lemma c_decide_eq:
  "c_decide pol s d r = find_decision pol s d r"
  by (induct pol) (simp_all add: find_cons find_decision_def)

(* Allow and Deny both pinned by evaluation on the demo matrix. *)
lemma c_decide_allow_ex:
  "c_decide demo_policy q_work q_net rpc_fetch = Allow"
  by eval

lemma c_decide_deny_ex:
  "c_decide demo_policy q_vault q_net rpc_fetch = Deny"
  by eval

lemma c_decide_ask_ex:
  "c_decide demo_policy q_work q_vault rpc_sign = Ask"
  by eval

(* ---- C call path (mirrors qube_decide + qube_ask_enqueue) ---- *)

definition c_q_call :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> qstate \<Rightarrow> qstate" where
  "c_q_call src dst rpc h st =
   (case c_decide (policy st) src dst rpc of
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

(* Refinement: the C call path equals the spec transition. *)
lemma c_q_call_refines:
  "c_q_call s d r h st = q_call s d r h st"
  by (simp add: c_q_call_def q_call_def c_decide_eq split: decision.split)

(* Case split: Allow (room) / Ask-suspend / Ask-full (room) / Deny (room). *)
lemma c_call_allow_ref:
  assumes "c_decide (policy st) s d r = Allow"
      and "audit_room st"
  shows "audit (c_q_call s d r h st) =
           audit st @ [\<lparr>osrc = s, odst = d, orpc = r, oallow = True\<rparr>] \<and>
         pending (c_q_call s d r h st) = pending st"
  using assms by (simp add: c_q_call_refines q_call_def c_decide_eq)

lemma c_call_deny_ref:
  assumes "c_decide (policy st) s d r = Deny"
      and "audit_room st"
  shows "audit (c_q_call s d r h st) =
           audit st @ [\<lparr>osrc = s, odst = d, orpc = r, oallow = False\<rparr>] \<and>
         pending (c_q_call s d r h st) = pending st"
  using assms by (simp add: c_q_call_refines q_call_def c_decide_eq)

lemma c_call_ask_suspend_ref:
  assumes "c_decide (policy st) s d r = Ask"
      and "length (pending st) < max_pending"
  shows "audit (c_q_call s d r h st) = audit st \<and>
         pending (c_q_call s d r h st) =
           pending st @ [\<lparr>asrc = s, adst = d, arpc = r, ahash = h\<rparr>]"
  using assms by (simp add: c_q_call_refines q_call_def c_decide_eq)

lemma c_call_ask_full_ref:
  assumes "c_decide (policy st) s d r = Ask"
      and "\<not> length (pending st) < max_pending"
      and "audit_room st"
  shows "audit (c_q_call s d r h st) =
           audit st @ [\<lparr>osrc = s, odst = d, orpc = r, oallow = False\<rparr>] \<and>
         pending (c_q_call s d r h st) = pending st"
  using assms by (simp add: c_q_call_refines q_call_def c_decide_eq)

(* Full audit blocks Allow at the C level (fail-closed, via refinement). *)
lemma c_full_blocks_allow:
  assumes "length (audit st) \<ge> max_audit"
      and "c_decide (policy st) s d r = Allow"
  shows "c_q_call s d r h st = st"
  using assms by (simp add: c_q_call_refines c_decide_eq audit_full_blocks_allow)

(* Executable pins: C-level Allow, Deny, and full-queue Ask-to-Deny. *)
lemma c_demo_allow_audit:
  "audit (c_q_call q_work q_net rpc_fetch 7 demo_init) =
   [\<lparr>osrc = q_work, odst = q_net, orpc = rpc_fetch, oallow = True\<rparr>]"
  by eval

lemma c_demo_deny_audit:
  "audit (c_q_call q_vault q_net rpc_fetch 7 demo_init) =
   [\<lparr>osrc = q_vault, odst = q_net, orpc = rpc_fetch, oallow = False\<rparr>]"
  by eval

lemma c_demo_ask_full_denies:
  "audit (c_q_call q_work q_vault rpc_sign 9
           (demo_init\<lparr>pending :=
              replicate 32 \<lparr>asrc = 0, adst = 0, arpc = 0, ahash = 0\<rparr>\<rparr>)) =
   [\<lparr>osrc = q_work, odst = q_vault, orpc = rpc_sign, oallow = False\<rparr>]"
  by eval

(* ---- C decide path (mirrors qube_decide_idx) ---- *)

(* Dequeue-then-best-effort-audit: the entry is always removed, the
   verdict record lands iff room (the approve-deliver full path dequeues
   as deny with no actuation). *)
definition c_q_decide :: "nat \<Rightarrow> bool \<Rightarrow> qstate \<Rightarrow> qstate" where
  "c_q_decide i approve st =
   (if i < length (pending st) then
      let a = pending st ! i in
      st\<lparr>pending := pending_del i (pending st),
          audit := audit st @
                   (if audit_room st
                    then [\<lparr>osrc = asrc a, odst = adst a, orpc = arpc a, oallow = approve\<rparr>]
                    else [])\<rparr>
    else st)"

(* Refinement: the C decide path equals the spec transition. *)
lemma c_q_decide_refines:
  "c_q_decide i a st = q_decide i a st"
  by (simp add: c_q_decide_def q_decide_def)

(* Deny still proceeds at the C level: dequeue is unconditional. *)
lemma c_decide_always_dequeues:
  "i < length (pending st) \<Longrightarrow>
   pending (c_q_decide i a st) = pending_del i (pending st)"
  by (simp add: c_q_decide_refines decide_always_dequeues)

(* ---- C destroy sweep (mirrors qube_destroy_drop) ---- *)

(* Recursive read/write sweep: keep entries touching neither side. *)
fun c_keep :: "nat \<Rightarrow> ask list \<Rightarrow> ask list" where
  "c_keep q [] = []" |
  "c_keep q (a # at) =
    (if asrc a = q \<or> adst a = q then c_keep q at else a # c_keep q at)"

(* Dropped entries: the ones the sweep denies and audits. *)
fun c_dropped :: "nat \<Rightarrow> ask list \<Rightarrow> ask list" where
  "c_dropped q [] = []" |
  "c_dropped q (a # at) =
    (if asrc a = q \<or> adst a = q then a # c_dropped q at else c_dropped q at)"

lemma c_keep_eq:
  "c_keep q p = filter (\<lambda>a. asrc a \<noteq> q \<and> adst a \<noteq> q) p"
  by (induct p) simp_all

lemma c_dropped_eq:
  "c_dropped q p = filter (\<lambda>a. asrc a = q \<or> adst a = q) p"
  by (induct p) simp_all

definition c_q_destroy :: "nat \<Rightarrow> qstate \<Rightarrow> qstate" where
  "c_q_destroy q st =
   (let dropped = c_dropped q (pending st);
        newrecs = map (\<lambda>a. \<lparr>osrc = asrc a, odst = adst a,
                               orpc = arpc a, oallow = False\<rparr>) dropped in
    st\<lparr>qubes := filter (\<lambda>x. x \<noteq> q) (qubes st),
        pending := c_keep q (pending st),
        audit := audit st @ take (max_audit - length (audit st)) newrecs\<rparr>)"

(* Refinement: the C sweep equals the spec destroy. *)
lemma c_q_destroy_refines:
  "c_q_destroy q st = q_destroy q st"
  by (simp add: c_q_destroy_def q_destroy_def c_keep_eq c_dropped_eq Let_def)

(* Pending-filter + capped-audit shape, stated for the C operator. *)
lemma c_destroy_filter:
  "pending (c_q_destroy q st) =
     filter (\<lambda>a. asrc a \<noteq> q \<and> adst a \<noteq> q) (pending st) \<and>
   audit (c_q_destroy q st) = audit st @
     take (max_audit - length (audit st))
       (map (\<lambda>a. \<lparr>osrc = asrc a, odst = adst a,
                     orpc = arpc a, oallow = False\<rparr>)
         (filter (\<lambda>a. asrc a = q \<or> adst a = q) (pending st)))"
  by (simp add: c_q_destroy_refines q_destroy_def destroy_audit_capped
                c_keep_eq Let_def)

(* Destroy denies (never allows) in-flight asks at the C level. *)
lemma c_destroy_denies:
  "\<forall>e \<in> set (audit (c_q_destroy q st)) - set (audit st). \<not> oallow e"
  by (simp add: c_q_destroy_refines destroy_denies_inflight)

(* Executable pin: destroying the caller drops its ask as Deny. *)
lemma c_demo_destroy_denies:
  "audit (c_q_destroy q_work (q_call q_work q_vault rpc_sign 9 demo_init)) =
   [\<lparr>osrc = q_work, odst = q_vault, orpc = rpc_sign, oallow = False\<rparr>] \<and>
   pending (c_q_destroy q_work (q_call q_work q_vault rpc_sign 9 demo_init)) = []"
  by eval

(* ---- Preservation across the C operators ---- *)

lemma c_call_unique:
  "q_unique st \<Longrightarrow> q_unique (c_q_call s d r h st)"
  by (simp add: c_q_call_refines call_unique)

lemma c_call_bounded:
  "q_bounded st \<Longrightarrow> q_bounded (c_q_call s d r h st)"
  by (simp add: c_q_call_refines call_bounded)

lemma c_call_pbounded:
  "p_bounded st \<Longrightarrow> p_bounded (c_q_call s d r h st)"
  by (simp add: c_q_call_refines call_pbounded)

lemma c_call_policy:
  "c_policy_bounded st \<Longrightarrow> c_policy_bounded (c_q_call s d r h st)"
  by (simp add: c_q_call_refines c_policy_bounded_def q_call_def split: decision.split)

lemma c_destroy_unique:
  "q_unique st \<Longrightarrow> q_unique (c_q_destroy q st)"
  by (simp add: c_q_destroy_refines destroy_unique)

lemma c_destroy_bounded:
  "q_bounded st \<Longrightarrow> q_bounded (c_q_destroy q st)"
  by (simp add: c_q_destroy_refines destroy_bounded)

lemma c_destroy_pbounded:
  "p_bounded st \<Longrightarrow> p_bounded (c_q_destroy q st)"
  by (simp add: c_q_destroy_refines destroy_pbounded)

lemma c_destroy_policy:
  "c_policy_bounded st \<Longrightarrow> c_policy_bounded (c_q_destroy q st)"
  by (simp add: c_q_destroy_def c_policy_bounded_def Let_def)

(* ---- Mutants: every invariant can fail ---- *)

definition mutant_b_dup :: qstate where
  "mutant_b_dup = init_qstate\<lparr>qubes := [4, 4]\<rparr>"

lemma mutant_b_dup_bad: "\<not> q_unique mutant_b_dup"
  by (simp add: mutant_b_dup_def q_unique_def)

definition mutant_b_many :: qstate where
  "mutant_b_many =
   init_qstate\<lparr>qubes := [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]\<rparr>"

lemma mutant_b_many_bad: "\<not> q_bounded mutant_b_many"
  by (simp add: mutant_b_many_def q_bounded_def max_qubes_def)

definition mutant_b_pend :: qstate where
  "mutant_b_pend =
   init_qstate\<lparr>pending :=
     replicate 33 \<lparr>asrc = 1, adst = 2, arpc = 1, ahash = 0\<rparr>\<rparr>"

lemma mutant_b_pend_bad: "\<not> p_bounded mutant_b_pend"
  by (simp add: mutant_b_pend_def p_bounded_def max_pending_def)

(* Strictness witness: 10 qubes fit the spec but overflow the C table. *)
definition mutant_b_c9 :: qstate where
  "mutant_b_c9 = init_qstate\<lparr>qubes := [0,1,2,3,4,5,6,7,8,9]\<rparr>"

lemma mutant_b_c9_bad: "\<not> c_qbounded mutant_b_c9"
  by (simp add: mutant_b_c9_def c_qbounded_def c_max_qubes_def)

lemma mutant_b_c9_spec_ok: "q_bounded mutant_b_c9"
  by (simp add: mutant_b_c9_def q_bounded_def max_qubes_def)

(* Policy overflow witness: 33 rules exceed the C table. *)
definition mutant_b_policy :: qstate where
  "mutant_b_policy =
   init_qstate\<lparr>policy :=
     replicate 33 \<lparr>rs = None, rd = None, rr = 0, rdec = Deny\<rparr>\<rparr>"

lemma mutant_b_policy_bad: "\<not> c_policy_bounded mutant_b_policy"
  by (simp add: mutant_b_policy_def c_policy_bounded_def c_max_policy_def)

lemma b_invariants_nontrivial:
  "(\<exists>s. \<not> q_unique s) \<and> (\<exists>s. \<not> q_bounded s) \<and> (\<exists>s. \<not> p_bounded s) \<and>
   (\<exists>s. \<not> a_bounded s) \<and>
   (\<exists>s. \<not> c_qbounded s) \<and> (\<exists>s. q_bounded s \<and> \<not> c_qbounded s) \<and>
   (\<exists>s. \<not> c_policy_bounded s) \<and>
   (\<exists>L s d. \<not> raw_ok L False s d)"
  using mutant_b_dup_bad mutant_b_many_bad mutant_b_pend_bad
        mutant_audit_full_bad
        mutant_b_c9_bad mutant_b_c9_spec_ok mutant_b_policy_bad
        mutant_forge_bad
  by blast

end
