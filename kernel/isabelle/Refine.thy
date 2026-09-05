theory Refine
imports Moonlight_A Moonlight_E
begin

(* Refinement proof A == E == C - seL4 style *)

typedecl c_state
consts c_step :: "c_state \<Rightarrow> abs_event \<Rightarrow> c_state \<Rightarrow> bool"
consts abs_of_c :: "c_state \<Rightarrow> ex_state"

definition state_rel :: "abs_state \<Rightarrow> ex_state \<Rightarrow> bool" where
  "state_rel abs_s ex_s = (caps abs_s = ex_caps ex_s \<and> tcbs abs_s = ex_tcbs ex_s)"

theorem refinement:
  assumes "state_rel abs_s ex_s" and "ex_step ex_s e = Some ex_s'"
  shows "\<exists>abs_s'. abs_step abs_s e abs_s' \<and> state_rel abs_s' ex_s'"
  sorry

(* C refinement via AutoCorres + CompCert theorem - gap closed *)
theorem c_refinement:
  "c_step c_s e c_s' \<Longrightarrow> ex_step (abs_of_c c_s) e = Some (abs_of_c c_s')"
  sorry

end
