theory Sched_Verification
imports Moonlight_A
begin

type_synonym sched_state = nat
consts sc_budget :: "nat \<Rightarrow> nat"
consts sc_period :: "nat \<Rightarrow> nat"
consts sc_partition :: "nat \<Rightarrow> partition"
consts schedulable2 :: "sched_state \<Rightarrow> partition \<Rightarrow> bool"
consts kernel_path :: "partition \<Rightarrow> bool"
consts wcet :: "partition \<Rightarrow> nat"
consts cur_partition :: "sched_state \<Rightarrow> partition"
consts flush_microarch :: "sched_state \<Rightarrow> sched_state \<Rightarrow> bool"
consts sched_tick :: "sched_state \<Rightarrow> nat \<Rightarrow> sched_state"

(* Real-time schedulability + WCET - missing in seL4 *)

definition utilization :: "sched_state \<Rightarrow> partition \<Rightarrow> nat" where
  "utilization s p = 0"

theorem edf_schedulable:
  "utilization s p \<le> (1::nat) \<Longrightarrow> schedulable2 s p"
  sorry

theorem wcet_bound:
  "kernel_path p \<Longrightarrow> wcet p \<le> 5000" (* 5us in cycles *)
  sorry

theorem partition_isolation_time:
  "cur_partition s \<noteq> cur_partition s' \<Longrightarrow> flush_microarch s s'"
  sorry

end
