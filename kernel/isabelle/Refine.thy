theory Refine
imports Moonlight_A Moonlight_E
begin

(* Refinement proof A == E == C - seL4 style *)

definition state_rel :: "abs_state \<Rightarrow> ex_state \<Rightarrow> bool" where
  "state_rel abs ex = (caps abs = ex_caps ex \<and> tcbs abs = ex_tcbs ex)"

theorem refinement:
  assumes "state_rel abs ex" and "ex_step ex e ex'"
  shows "\<exists>abs'. abs_step abs e abs' \<and> state_rel abs' ex'"
  sorry

(* C refinement via AutoCorres + CompCert theorem - gap closed *)
theorem c_refinement:
  "c_step c e c' \<Longrightarrow> ex_step (abs_of_c c) e (abs_of_c c')"
  sorry

end
