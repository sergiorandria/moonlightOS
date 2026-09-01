theory Sched_Verification
imports Moonlight_A
begin

(* Real-time schedulability + WCET - missing in seL4 *)

definition utilization :: "sched_state \<Rightarrow> partition \<Rightarrow> real" where
  "utilization s p = sum (\<lambda>sc. budget sc / period sc) {sc. partition sc = p}"

theorem edf_schedulable:
  "utilization s p \<le> 1 \<Longrightarrow> schedulable s p"
  sorry

theorem wcet_bound:
  "kernel_path p \<Longrightarrow> wcet p \<le> 5000" (* 5us in cycles *)
  sorry

theorem partition_isolation_time:
  "cur_partition s \<noteq> cur_partition s' \<Longrightarrow> flush_microarch s s'"
  sorry

end
