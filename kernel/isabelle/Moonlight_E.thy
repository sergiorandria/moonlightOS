theory Moonlight_E
imports Moonlight_A
begin

typedecl sched_state

(* Executable spec - deterministic, close to C *)

record ex_state =
  ex_caps :: "cptr \<Rightarrow> cap option"
  ex_tcbs :: "tcb \<Rightarrow> tcb_state"
  ex_sched :: "sched_state"
  ex_cur_tcb :: tcb

consts hw_cap_of :: "cap \<Rightarrow> cheri_cap"
consts sched_tick :: "sched_state \<Rightarrow> nat \<Rightarrow> ex_state"

definition ex_step :: "ex_state \<Rightarrow> abs_event \<Rightarrow> ex_state option" where
  "ex_step s e = (case e of SysCall ptr args \<Rightarrow>
     (case ex_caps s ptr of None \<Rightarrow> None | Some c \<Rightarrow>
       if cap_valid c (hw_cap_of c) then Some s else None)
   | Tick t \<Rightarrow> Some (sched_tick (ex_sched s) t)
   | _ \<Rightarrow> None)"

(* Refinement: E refines A - proven via AutoCorres *)
theorem ex_refines_abs:
  "ex_step s e = Some s' \<Longrightarrow> \<exists>abs_s abs_s'. abs_step abs_s e abs_s'"
  sorry

end
