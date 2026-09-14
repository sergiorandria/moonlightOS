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

(* Scheduler (Stage 0, safety only): pick the lowest-numbered Runnable
   thread; no Runnable (or empty) \<Rightarrow> state unchanged. O(n), n \<le> max_threads.
   Fairness (round-robin-from-cur, "every Runnable is eventually picked")
   is a LIVENESS property and explicit Stage-1 work (V2_DESIGN Sec.7):
   Stage 0 proves the step is safe and lands on Runnable. Candidates are
   a SET so selection needs no hd/filter plumbing. *)
definition sched_cands :: "astate \<Rightarrow> nat set" where
  "sched_cands s = {i \<in> {0..<length (threads s)}. threads s ! i = Runnable}"

definition sched_step :: "astate \<Rightarrow> astate" where
  "sched_step s = (if sched_cands s = {} then s
                   else s(|cur := Min (sched_cands s)|))"

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

lemma min_cand_bound:
  "{i. i < length (threads s) \<and> threads s ! i = Runnable} \<noteq> {} \<Longrightarrow>
   Min {i. i < length (threads s) \<and> threads s ! i = Runnable}
   < length (threads s)"
proof -
  assume ne: "{i. i < length (threads s) \<and> threads s ! i = Runnable} \<noteq> {}"
  have MinS: "Min {i. i < length (threads s) \<and> threads s ! i = Runnable}
              \<in> {i. i < length (threads s) \<and> threads s ! i = Runnable}"
    by (rule Min_in[OF cands_finite ne])
  then show ?thesis by simp
qed

lemma step_valid: "valid_ids s \<Longrightarrow> valid_ids (sched_step s)"
  unfolding sched_step_def sched_cands_def valid_ids_def
  apply (simp split: if_split)
  apply (rule impI)
  apply (rule min_cand_bound)
  apply (auto simp: ex_in_conv)
  done

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
  unfolding sched_step_def
proof -
  assume ex: "\<exists>t \<in> set (threads s). t = Runnable"
  show "threads (if sched_cands s = {} then s
                 else s(|cur := Min (sched_cands s)|)) !
        cur (if sched_cands s = {} then s
             else s(|cur := Min (sched_cands s)|)) = Runnable"
  proof (cases "sched_cands s = {}")
    case True
    obtain i where ilt: "i < length (threads s)"
                 and ir: "threads s ! i = Runnable"
      using ex by (auto simp: in_set_conv_nth)
    have iS: "i \<in> sched_cands s"
      unfolding sched_cands_def using ilt ir by simp
    have False using iS True by simp
    then show ?thesis by simp
  next
    case False
    have sub: "{i. i < length (threads s) \<and> threads s ! i = Runnable}
               \<subseteq> {..<length (threads s)}" by auto
    have fin: "finite {i. i < length (threads s) \<and> threads s ! i = Runnable}"
      by (rule finite_subset[OF sub finite_lessThan])
    have neS: "{i. i < length (threads s) \<and> threads s ! i = Runnable} \<noteq> {}"
      using False unfolding sched_cands_def by simp
    have MinS: "Min {i. i < length (threads s) \<and> threads s ! i = Runnable}
                \<in> {i. i < length (threads s) \<and> threads s ! i = Runnable}"
      by (rule Min_in[OF fin neS])
    have Pj: "threads s ! Min (sched_cands s) = Runnable"
      using MinS unfolding sched_cands_def by simp
    show ?thesis using False Pj by simp
  qed
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

(* ---- Executable demo: two threads, suspend, two steps ---- *)

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
  "cur (sched_step (sched_step (tcb_suspend 0 (tcb_create (tcb_create init_state))))) = 1"
  by eval

end
