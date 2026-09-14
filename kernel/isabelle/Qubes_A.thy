theory Qubes_A
imports Main
begin

(* Moonlight Qubes isolation, Stage S0: abstract qube + policy model.
   Roadmap: docs/QUBES_ISOLATION_PLAN.md S0. Labels are nats minted by the
   (future) AdminVM; every cross-qube call carries its caller label the way
   ipc_msg_t.sender_tcb is kernel-stamped today. Policy is data: first
   matching rule wins, no match ==> Deny (fail closed). Ask suspends into a
   bounded pending queue; q_decide resolves one entry (the AdminVM confirm
   path). Audit is append-only. All functions total: full queues fail closed,
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
      Allow \<Rightarrow> st\<lparr>audit := audit st @
                         [\<lparr>osrc = src, odst = dst, orpc = rpc, oallow = True\<rparr>]\<rparr>
    | Ask \<Rightarrow> (if length (pending st) < max_pending
               then st\<lparr>pending := pending st @
                              [\<lparr>asrc = src, adst = dst, arpc = rpc, ahash = h\<rparr>]\<rparr>
               else st\<lparr>audit := audit st @
                              [\<lparr>osrc = src, odst = dst, orpc = rpc, oallow = False\<rparr>]\<rparr>)
    | Deny \<Rightarrow> st\<lparr>audit := audit st @
                        [\<lparr>osrc = src, odst = dst, orpc = rpc, oallow = False\<rparr>]\<rparr>)"

definition pending_del :: "nat \<Rightarrow> ask list \<Rightarrow> ask list" where
  "pending_del i p = take i p @ drop (Suc i) p"

definition q_decide :: "nat \<Rightarrow> bool \<Rightarrow> qstate \<Rightarrow> qstate" where
  "q_decide i approve st =
   (if i < length (pending st) then
      let a = pending st ! i in
      st\<lparr>pending := pending_del i (pending st),
          audit := audit st @
                   [\<lparr>osrc = asrc a, odst = adst a, orpc = arpc a, oallow = approve\<rparr>]\<rparr>
    else st)"

definition q_destroy :: "nat \<Rightarrow> qstate \<Rightarrow> qstate" where
  "q_destroy q st =
   (let dropped = filter (\<lambda>a. asrc a = q \<or> adst a = q) (pending st) in
    st\<lparr>qubes := filter (\<lambda>x. x \<noteq> q) (qubes st),
        pending := filter (\<lambda>a. asrc a \<noteq> q \<and> adst a \<noteq> q) (pending st),
        audit := audit st @
                 map (\<lambda>a. \<lparr>osrc = asrc a, odst = adst a,
                               orpc = arpc a, oallow = False\<rparr>) dropped\<rparr>)"

(* ---- Invariants (real predicates, not True) ---- *)

definition q_unique :: "qstate \<Rightarrow> bool" where
  "q_unique st = distinct (qubes st)"

definition q_bounded :: "qstate \<Rightarrow> bool" where
  "q_bounded st = (length (qubes st) \<le> max_qubes)"

definition p_bounded :: "qstate \<Rightarrow> bool" where
  "p_bounded st = (length (pending st) \<le> max_pending)"

lemma init_invs:
  "q_unique init_qstate \<and> q_bounded init_qstate \<and> p_bounded init_qstate"
  by (simp add: init_qstate_def q_unique_def q_bounded_def p_bounded_def
               max_qubes_def max_pending_def)

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

lemma destroy_unique: "q_unique st \<Longrightarrow> q_unique (q_destroy q st)"
  unfolding q_destroy_def q_unique_def Let_def
  by (simp add: distinct_filter)

lemma destroy_bounded: "q_bounded st \<Longrightarrow> q_bounded (q_destroy q st)"
  unfolding q_destroy_def q_bounded_def Let_def
  by (simp add: order_trans[OF length_filter_le])

lemma destroy_pbounded: "p_bounded st \<Longrightarrow> p_bounded (q_destroy q st)"
  unfolding q_destroy_def p_bounded_def Let_def
  by (simp add: order_trans[OF length_filter_le])

(* ---- Security theorems ---- *)

(* Denied calls audit Deny and never touch the pending queue. *)
lemma call_deny_closed:
  "find_decision (policy st) s d r = Deny \<Longrightarrow>
   audit (q_call s d r h st) =
     audit st @ [\<lparr>osrc = s, odst = d, orpc = r, oallow = False\<rparr>] \<and>
   pending (q_call s d r h st) = pending st"
  by (simp add: q_call_def)

(* Default-deny: no matching rule ==> Deny. *)
lemma call_default_deny:
  "filter (\<lambda>rl. match_rule rl s d r) (policy st) = [] \<Longrightarrow>
   audit (q_call s d r h st) =
     audit st @ [\<lparr>osrc = s, odst = d, orpc = r, oallow = False\<rparr>]"
  by (simp add: q_call_def find_decision_def)

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
  unfolding q_call_def max_pending_def
  by (auto split: decision.split if_split)

(* Shape of every call outcome: audit unchanged, one Deny appended, or one
   rule-backed Allow appended. Pure case enumeration, feeds the two
   no-bypass/no-forge theorems below. *)
lemma q_call_audit_cases:
  "audit (q_call s d r h st) = audit st \<or>
   (\<exists>e. audit (q_call s d r h st) = audit st @ [e] \<and> \<not> oallow e) \<or>
   (audit (q_call s d r h st) =
      audit st @ [\<lparr>osrc = s, odst = d, orpc = r, oallow = True\<rparr>] \<and>
    find_decision (policy st) s d r = Allow)"
  unfolding q_call_def
  by (auto split: decision.split if_split)

(* Allow appends Allow only by rule (single-step, no forge). *)
lemma allow_only_by_rule:
  "oallow e \<Longrightarrow>
   e \<in> set (audit (q_call s d r h st)) - set (audit st) \<Longrightarrow>
   find_decision (policy st) s d r = Allow"
  using q_call_audit_cases[of s d r h st] by auto

(* Decide on a valid index resolves exactly that entry with the verdict. *)
lemma decide_approves:
  "i < length (pending st) \<Longrightarrow>
   audit (q_decide i True st) =
     audit st @ [\<lparr>osrc = asrc (pending st ! i),
                  odst = adst (pending st ! i),
                  orpc = arpc (pending st ! i), oallow = True\<rparr>] \<and>
   length (pending (q_decide i True st)) = length (pending st) - 1"
  unfolding q_decide_def Let_def
  by (simp split: if_split add: pending_del_len)

(* Decide on a bad index is a no-op (no silent allow). *)
lemma decide_bad_index:
  "\<not> i < length (pending st) \<Longrightarrow> q_decide i a st = st"
  by (simp add: q_decide_def)

(* Destroying a qube denies (never allows) its in-flight asks. *)
lemma destroy_denies_inflight:
  "\<forall>e \<in> set (audit (q_destroy q st)) - set (audit st). \<not> oallow e"
  unfolding q_destroy_def Let_def by auto

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

lemma invariants_nontrivial:
  "(\<exists>s. \<not> q_unique s) \<and> (\<exists>s. \<not> q_bounded s) \<and> (\<exists>s. \<not> p_bounded s)"
  using mutant_dup_bad mutant_many_bad mutant_pend_bad by blast

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

end
