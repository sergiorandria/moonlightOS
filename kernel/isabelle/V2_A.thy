theory V2_A
imports Main
begin

(* Moonlight v2, Stage 0: abstract TCB + round-robin on one address space.
   Roadmap: docs/V2_DESIGN.md Sec.9. hart0, single address space, no
   capabilities yet (Stage 3), no partitions yet (Stage 4).
   Threads are a LIST (not a function) so the spec is executable: the
   `value` commands at the end evaluate the schedule in CI output.
   Anti-vacuity (V2_DESIGN Sec.6): every invariant below is falsifiable --
   each ships with a mutant state that violates it. Zero axioms. *)

datatype tstate = Runnable | Blocked | Inactive

definition max_threads :: nat where
  "max_threads = 8"

record astate =
  threads :: "tstate list"
  cur :: nat

definition init_state :: astate where
  "init_state = (|threads = [Runnable], cur = 0|)"

(* Total functions: full/empty/bad-index are no-ops, never undefined. *)

definition tcb_create :: "astate \<Rightarrow> astate" where
  "tcb_create s = (if length (threads s) < max_threads
                   then s(|threads := threads s @ [Runnable]|) else s)"

definition tcb_suspend :: "nat \<Rightarrow> astate \<Rightarrow> astate" where
  "tcb_suspend i s = (if i < length (threads s)
                      then s(|threads := (threads s)[i := Blocked]|) else s)"

definition tcb_resume :: "nat \<Rightarrow> astate \<Rightarrow> astate" where
  "tcb_resume i s = (if i < length (threads s)
                     then s(|threads := (threads s)[i := Runnable]|) else s)"

(* Scheduler: select the lowest Runnable TID strictly after cur, wrapping
   to the lowest Runnable TID when needed. This is round-robin by TID;
   no Runnable (or empty) leaves the state unchanged. O(n), n <= max_threads.
   Candidates are sets so both safety and concrete rotation traces are
   executable in the model. *)
definition sched_cands :: "astate \<Rightarrow> nat set" where
  "sched_cands s = {i \<in> {0..<length (threads s)}. threads s ! i = Runnable}"

definition sched_after :: "astate \<Rightarrow> nat set" where
  "sched_after s = {i \<in> sched_cands s. cur s < i}"

definition sched_pick :: "astate \<Rightarrow> nat" where
  "sched_pick s = (if sched_after s = {} then Min (sched_cands s)
                   else Min (sched_after s))"

definition sched_step :: "astate \<Rightarrow> astate" where
  "sched_step s = (if sched_cands s = {} then s
                   else s(|cur := sched_pick s|))"

(* ---- Invariants (real predicates, not True) ---- *)

definition valid_ids :: "astate \<Rightarrow> bool" where
  "valid_ids s = (cur s < length (threads s))"

definition bounded :: "astate \<Rightarrow> bool" where
  "bounded s = (length (threads s) \<le> max_threads)"

(* ---- Base: init establishes both ---- *)

lemma init_valid: "valid_ids init_state"
  by (simp add: init_state_def valid_ids_def)

lemma init_bounded: "bounded init_state"
  by (simp add: init_state_def bounded_def max_threads_def)

(* ---- Preservation: every transition keeps both ---- *)

lemma create_valid: "valid_ids s \<Longrightarrow> valid_ids (tcb_create s)"
  by (simp add: tcb_create_def valid_ids_def)

lemma create_bounded: "bounded s \<Longrightarrow> bounded (tcb_create s)"
  by (simp add: tcb_create_def bounded_def max_threads_def)

lemma suspend_valid: "valid_ids s \<Longrightarrow> valid_ids (tcb_suspend i s)"
  by (simp add: tcb_suspend_def valid_ids_def)

lemma suspend_bounded: "bounded s \<Longrightarrow> bounded (tcb_suspend i s)"
  by (simp add: tcb_suspend_def bounded_def)

lemma resume_valid: "valid_ids s \<Longrightarrow> valid_ids (tcb_resume i s)"
  by (simp add: tcb_resume_def valid_ids_def)

lemma resume_bounded: "bounded s \<Longrightarrow> bounded (tcb_resume i s)"
  by (simp add: tcb_resume_def bounded_def)

lemma cands_finite:
  "finite {i. i < length (threads s) \<and> threads s ! i = Runnable}"
proof -
  have sub: "{i. i < length (threads s) \<and> threads s ! i = Runnable}
             \<subseteq> {..<length (threads s)}" by auto
  show ?thesis by (rule finite_subset[OF sub finite_lessThan])
qed

lemma sched_after_subset: "sched_after s \<subseteq> sched_cands s"
  by (auto simp: sched_after_def)

lemma sched_pick_in:
  "sched_cands s \<noteq> {} \<Longrightarrow> sched_pick s \<in> sched_cands s"
proof -
  assume ne: "sched_cands s \<noteq> {}"
  have fin: "finite (sched_cands s)"
    using cands_finite[of s] by (simp add: sched_cands_def)
  have afin: "finite (sched_after s)"
    using finite_subset[OF sched_after_subset fin] .
  show ?thesis
  proof (cases "sched_after s = {}")
    case True
    have "Min (sched_cands s) \<in> sched_cands s"
      by (rule Min_in[OF fin ne])
    then show ?thesis using True by (simp add: sched_pick_def)
  next
    case False
    have "Min (sched_after s) \<in> sched_after s"
      by (rule Min_in[OF afin False])
    then show ?thesis
      using sched_after_subset by (auto simp: sched_pick_def False)
  qed
qed

lemma sched_pick_runnable:
  "sched_cands s \<noteq> {} \<Longrightarrow>
   sched_pick s < length (threads s) \<and>
   threads s ! sched_pick s = Runnable"
proof -
  assume ne: "sched_cands s \<noteq> {}"
  have member: "sched_pick s \<in> sched_cands s"
    by (rule sched_pick_in[OF ne])
  then show ?thesis
    unfolding sched_cands_def by auto
qed

lemma step_valid: "valid_ids s \<Longrightarrow> valid_ids (sched_step s)"
proof -
  assume valid: "valid_ids s"
  show ?thesis
  proof (cases "sched_cands s = {}")
    case True
    then show ?thesis using valid True by (simp add: sched_step_def valid_ids_def)
  next
    case False
    then have bound: "sched_pick s < length (threads s)"
      using sched_pick_runnable by blast
    show ?thesis using bound False by (simp add: sched_step_def valid_ids_def)
  qed
qed

lemma step_bounded: "bounded s \<Longrightarrow> bounded (sched_step s)"
  unfolding sched_step_def bounded_def
  by (auto split: if_split)

(* ---- Functional: create appends Runnable; step lands on Runnable ---- *)

lemma create_makes_runnable:
  "length (threads s) < max_threads \<Longrightarrow>
   threads (tcb_create s) ! length (threads s) = Runnable"
  by (simp add: tcb_create_def)

lemma step_picks_runnable:
  "\<exists>t \<in> set (threads s). t = Runnable \<Longrightarrow>
   threads (sched_step s) ! cur (sched_step s) = Runnable"
proof -
  assume ex: "\<exists>t \<in> set (threads s). t = Runnable"
  have ne: "sched_cands s \<noteq> {}"
    using ex by (auto simp: sched_cands_def in_set_conv_nth)
  have chosen: "threads s ! sched_pick s = Runnable"
    using sched_pick_runnable[OF ne] by simp
  show ?thesis
    using chosen ne by (simp add: sched_step_def)
qed

(* ---- Mutants: each invariant CAN fail (anti-vacuity rule 2) ---- *)

definition mutant_cur :: astate where
  "mutant_cur = (|threads = [Runnable], cur = 7|)"

lemma mutant_cur_bad: "\<not> valid_ids mutant_cur"
  by (simp add: mutant_cur_def valid_ids_def)

definition mutant_big :: astate where
  "mutant_big = (|threads = replicate 9 Runnable, cur = 0|)"

lemma mutant_big_bad: "\<not> bounded mutant_big"
  by (simp add: mutant_big_def bounded_def max_threads_def)

lemma invariants_nontrivial:
  "(\<exists>s. \<not> valid_ids s) \<and> (\<exists>s. \<not> bounded s)"
  using mutant_cur_bad mutant_big_bad by blast

(* ---- Executable demos: safety and round-robin rotation ---- *)

value "let s0 = init_state;
           s1 = tcb_create s0;
           s2 = tcb_create s1
       in map cur [s0, s1, s2, sched_step s2]"

value "let s = tcb_suspend 0 (tcb_create (tcb_create init_state)) in
       (threads s, cur (sched_step s), cur (sched_step (sched_step s)))"

(* Machine-checked demo values (CI-verified, not just printed). *)
lemma demo_create_two:
  "threads (tcb_create (tcb_create init_state)) = [Runnable, Runnable, Runnable]"
  by eval

lemma demo_step_picks_1:
  "cur (sched_step (tcb_suspend 0 (tcb_create (tcb_create init_state)))) = 1"
  by eval

lemma demo_step_stable:
  "cur (sched_step (sched_step (tcb_suspend 0 (tcb_create (tcb_create init_state))))) = 2"
  by eval

lemma demo_round_robin:
  "let s0 = tcb_create (tcb_create init_state)
   in map cur [s0, sched_step s0, sched_step (sched_step s0),
               sched_step (sched_step (sched_step s0))] = [0, 1, 2, 0]"
  by eval

end
