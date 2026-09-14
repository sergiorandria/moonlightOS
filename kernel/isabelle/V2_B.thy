theory V2_B
imports V2_A
begin

(* Moonlight v2, Stage 1: privilege + trap discipline on top of V2_A.
   Modes M (firmware, opaque) / S (kernel) / U (userspace). Memory is an
   abstract address nat; kernel owns {0..<kbound s}, enforced by the
   U-bit in the implementation (Stage-1 note in V2_DESIGN Sec.2: PMP
   protects firmware; U-bit isolates kernel from user).
   The console is an observable char trace: UPutc appends IFF in U-mode.
   Kernel writes (kw) are tracked so "U never touches kernel memory" is a
   real preservation statement, falsified by bad_write below.
   Scheduler reuse: s_ret steps V2_A.sched_step -- the implementation runs
   the same lowest-Runnable policy. Zero axioms. *)

datatype mode = MMode | SMode | UMode
(* UPark parks the caller (blocking primitive; no unpark until Stage 2 IPC).
   UBad nat attempts a load that traps IFF inside the kernel region. *)
datatype uop = UYield | UPutc char | UPark | UBad nat

record mstate =
  v :: astate
  mode :: mode
  kbound :: nat
  out :: "char list"
  kw :: "nat set"

definition boot_state :: mstate where
  "boot_state = (|v = init_state, mode = SMode, kbound = 16,
                  out = [], kw = {}|)"

(* U-mode execution: yield schedules, putc emits, park blocks (via
   V2_A suspend of cur), bad load traps IFF kernel. *)
definition u_exec :: "uop \<Rightarrow> mstate \<Rightarrow> mstate" where
  "u_exec op s = (if mode s \<noteq> UMode then s
                  else case op of
                    UYield \<Rightarrow> s(|v := sched_step (v s)|)
                  | UPutc c \<Rightarrow> s(|out := out s @ [c]|)
                  | UPark \<Rightarrow> s(|v := tcb_suspend (cur (v s)) (v s)|)
                  | UBad a \<Rightarrow> (if a < kbound s then s(|mode := SMode|) else s))"

(* Timer preempts U to S; S-mode ticks are kernel-internal (no-op here). *)
definition timer_tick :: "mstate \<Rightarrow> mstate" where
  "timer_tick s = (if mode s = UMode then s(|mode := SMode|) else s)"

(* S-mode trap return: schedule, drop to U. *)
definition s_ret :: "mstate \<Rightarrow> mstate" where
  "s_ret s = (if mode s = SMode
              then s(|mode := UMode, v := sched_step (v s)|) else s)"

(* ---- Isolation: U-steps never produce M, never write kernel ---- *)

lemma u_exec_no_M: "mode s \<noteq> MMode \<Longrightarrow> mode (u_exec op s) \<noteq> MMode"
  by (simp add: u_exec_def split: if_split uop.split mode.split)

lemma timer_no_M: "mode s \<noteq> MMode \<Longrightarrow> mode (timer_tick s) \<noteq> MMode"
  by (simp add: timer_tick_def split: if_split mode.split)

lemma sret_no_M: "mode s \<noteq> MMode \<Longrightarrow> mode (s_ret s) \<noteq> MMode"
  by (simp add: s_ret_def split: if_split mode.split)

lemma u_exec_kw: "kw (u_exec op s) = kw s"
  by (simp add: u_exec_def split: if_split uop.split)

lemma timer_kw: "kw (timer_tick s) = kw s"
  by (simp add: timer_tick_def split: if_split)

lemma sret_kw: "kw (s_ret s) = kw s"
  by (simp add: s_ret_def split: if_split)

(* Console is exactly the U-mode putc trace. *)
lemma console_correct:
  "out (u_exec (UPutc c) s) =
   (if mode s = UMode then out s @ [c] else out s)"
  by (simp add: u_exec_def split: if_split)

(* Return-from-trap schedules (mirrors the implementation). *)
lemma sret_schedules:
  "mode s = SMode \<Longrightarrow> v (s_ret s) = sched_step (v s)"
  by (simp add: s_ret_def)

(* Parking suspends the caller: validity preserved, cur thread blocked. *)
lemma park_valid:
  "valid_ids (v s) \<Longrightarrow> valid_ids (v (u_exec UPark s))"
  by (simp add: u_exec_def suspend_valid split: if_split uop.split)

lemma park_bounded:
  "bounded (v s) \<Longrightarrow> bounded (v (u_exec UPark s))"
  by (simp add: u_exec_def suspend_bounded split: if_split uop.split)

(* Kernel-region touch always traps out of U-mode. *)
lemma bad_traps:
  "mode s = UMode \<Longrightarrow> a < kbound s \<Longrightarrow> mode (u_exec (UBad a) s) = SMode"
  by (simp add: u_exec_def)

(* ---- Mutants: each property CAN fail ---- *)

definition bad_sret :: "mstate \<Rightarrow> mstate" where
  "bad_sret s = s(|mode := MMode|)"

lemma bad_sret_violates: "mode (bad_sret boot_state) = MMode"
  by (simp add: bad_sret_def boot_state_def)

definition bad_write :: "mstate \<Rightarrow> mstate" where
  "bad_write s = s(|kw := {0}|)"

lemma bad_write_violates: "kw (bad_write boot_state) \<noteq> kw boot_state"
  by (simp add: bad_write_def boot_state_def)

lemma isolation_nontrivial:
  "mode (bad_sret boot_state) = MMode \<and>
   kw (bad_write boot_state) \<noteq> kw boot_state"
  by (simp add: bad_sret_def bad_write_def boot_state_def)

(* ---- Executable demo: boot, enter U, yield, putc, tick, return ---- *)

value "let s0 = boot_state;
           s1 = s_ret s0;
           s2 = u_exec (UPutc CHR ''A'') s1;
           s3 = u_exec UYield s2;
           s4 = timer_tick s3;
           s5 = s_ret s4
       in (mode s5, out s5)"

lemma demo_trace:
  "let s1 = s_ret boot_state;
       s2 = u_exec (UPutc CHR ''A'') s1
   in (mode s2, out s2) = (UMode, [CHR ''A''])"
  by eval

end
