theory V2_C
imports V2_B
begin

(* Moonlight v2, Stage 2: endpoints + notifications, bidirectional IPC.
   Roadmap: docs/V2_DESIGN.md Sec.4 (copy discipline) + Sec.9 Stage 2
   (IPC integrity theorem, ping-pong demo). One static endpoint EP0
   (endpoint caps arrive with Stage 3); messages are bounded word lists;
   sender ids are kernel-stamped, never user-supplied.
   Copy discipline (enforced by the implementation, mirrored here by the
   in/out split of the transitions): SEND copies IN, RECV copies OUT,
   CALL would be both (userspace-composed from SEND+RECV until Stage 3
   reply caps exist), NOTIFY/WAIT carry no data.
   Blocking rendezvous: SEND with no waiter suspends the sender and
   queues (fail-closed when full); RECV with no sender suspends the
   receiver and records the waiter. Delivery appends (sender, full msg)
   to `got`; every accepted send appends to `sent`, so integrity is the
   subset `set got \<subseteq> set sent` (no forge) plus pairing by
   construction (no splice) plus an explicit overflow flag (no silent
   cut). Notifications are per-thread signal sets (OR-accumulate,
   non-blocking send, blocking wait). Zero axioms. *)

definition max_msg_len :: nat where
  "max_msg_len = 4"

definition max_ipc_q :: nat where
  "max_ipc_q = 16"

definition msg_ok :: "nat list \<Rightarrow> bool" where
  "msg_ok m = (length m \<le> max_msg_len)"

(* cm = underlying machine (V2_B: modes, console, kw); sendq = queued
   (sender, msg) pairs (FIFO); recvq = waiting receivers (FIFO);
   sent = every accepted send (monotone history); got = every delivery;
   ntfy = per-thread pending signal sets; wk = per-thread wait kind
   (0 none, 1 send-blocked, 2 recv-blocked, 3 wait-blocked) so NOTIFY
   wakes only genuine waiters, never a thread blocked in rendezvous. *)

record cstate =
  cm :: mstate
  sendq :: "(nat \<times> nat list) list"
  recvq :: "nat list"
  sent :: "(nat \<times> nat list) list"
  got :: "(nat \<times> nat list) list"
  ntfy :: "nat \<Rightarrow> nat set"
  wk :: "nat \<Rightarrow> nat"

definition nthreads_of :: "cstate \<Rightarrow> nat" where
  "nthreads_of st = length (threads (v (cm st)))"

definition runnable_of :: "cstate \<Rightarrow> nat \<Rightarrow> bool" where
  "runnable_of st t = (t < nthreads_of st \<and>
    threads (v (cm st)) ! t = Runnable)"

definition init_cstate :: cstate where
  "init_cstate =
   (|cm = boot_state(|v := tcb_create (v boot_state)|),
     sendq = [], recvq = [],
     sent = [], got = [],
     ntfy = (\<lambda>_. {}), wk = (\<lambda>_. 0)|)"

(* ---- Transitions (total: bad id/length/full queue/non-runnable are
   no-ops or error returns, never undefined) ---- *)

(* SEND s m: accept (record in sent) and either hand off to the oldest
   waiter (resume it) or queue + suspend the sender. Returns ok flag. *)
definition c_send :: "nat \<Rightarrow> nat list \<Rightarrow> cstate \<Rightarrow> (cstate \<times> bool)" where
  "c_send s m st =
   (if \<not> msg_ok m \<or> \<not> runnable_of st s \<or> length (sendq st) \<ge> max_ipc_q
    then (st, False)
    else let st1 = st(|sent := sent st @ [(s, m)]|) in
    case recvq st of
      [] \<Rightarrow> ((st1(|sendq := sendq st @ [(s, m)],
                 wk := (wk st1)(s := 1),
                 cm := (cm st)(|v := tcb_suspend s (v (cm st))|)|)), True)
    | r # rs \<Rightarrow> ((st1(|recvq := rs,
                 got := got st @ [(s, m)],
                 wk := (wk st1)(r := 0),
                 cm := (cm st)(|v := tcb_resume r (v (cm st))|)|)), True))"

(* RECV r bl: deliver the oldest queued send (resume the sender,
   truncate to bl with an explicit overflow flag) or record the waiter
   + suspend. Returns (sender, delivered, overflow); (0, [], True) is
   the error shape (bad id / non-runnable), distinct from blocking
   (False flag, empty delivery). *)
definition c_recv :: "nat \<Rightarrow> nat \<Rightarrow> cstate \<Rightarrow> (cstate \<times> (nat \<times> nat list \<times> bool))" where
  "c_recv r bl st =
   (if r \<ge> nthreads_of st \<or> threads (v (cm st)) ! r \<noteq> Runnable
    then (st, (0, [], True))
    else case sendq st of
      [] \<Rightarrow> ((st(|recvq := recvq st @ [r],
                 wk := (wk st)(r := 2),
                 cm := (cm st)(|v := tcb_suspend r (v (cm st))|)|)), (0, [], False))
    | (s, m) # rest \<Rightarrow>
        let dlv = take bl m; ovf = (length m > bl) in
        ((st(|sendq := rest,
              got := got st @ [(s, m)],
              wk := (wk st)(s := 0),
              cm := (cm st)(|v := tcb_resume s (v (cm st))|)|)), (s, dlv, ovf)))"

(* NOTIFY t sig: OR-accumulate one signal on t (non-blocking). Wakes t
   IFF t is wait-blocked (wk = 3); a thread blocked in rendezvous keeps
   its block (its message/buffer stay queued). Bad id is a no-op. *)
definition c_notify :: "nat \<Rightarrow> nat \<Rightarrow> cstate \<Rightarrow> cstate" where
  "c_notify t sig st =
   (if t \<ge> nthreads_of st then st
    else let st1 = st(|ntfy := (ntfy st)(t := ntfy st t \<union> {sig})|) in
    if wk st t = 3 then
      st1(|wk := (wk st)(t := 0),
            cm := (cm st)(|v := tcb_resume t (v (cm st))|)|)
    else st1)"

(* WAIT t: take pending signals (clear + return) or suspend + return {}. *)
definition c_wait :: "nat \<Rightarrow> cstate \<Rightarrow> (cstate \<times> nat set)" where
  "c_wait t st =
   (if t \<ge> nthreads_of st then (st, {})
    else if ntfy st t \<noteq> {} then
      ((st(|ntfy := (ntfy st)(t := {}), wk := (wk st)(t := 0)|)), ntfy st t)
    else
      ((st(|wk := (wk st)(t := 3),
            cm := (cm st)(|v := tcb_suspend t (v (cm st))|)|)), {}))"

(* ---- Integrity predicate (falsifiable: see mutants below) ---- *)

definition c_integrity :: "cstate \<Rightarrow> bool" where
  "c_integrity st = (set (got st) \<subseteq> set (sent st))"

definition c_senders_valid :: "cstate \<Rightarrow> bool" where
  "c_senders_valid st =
   ((\<forall>(s, m) \<in> set (sendq st). s < nthreads_of st) \<and>
    (\<forall>(s, m) \<in> set (got st). s < nthreads_of st))"

definition c_msgs_ok :: "cstate \<Rightarrow> bool" where
  "c_msgs_ok st =
   ((\<forall>(s, m) \<in> set (sendq st). msg_ok m) \<and>
    (\<forall>(s, m) \<in> set (sent st). msg_ok m) \<and>
    (\<forall>(s, m) \<in> set (got st). msg_ok m))"

(* ---- Base: init establishes everything ---- *)

lemma ipc_init_valid: "valid_ids (v (cm init_cstate))"
  by (simp add: init_cstate_def init_state_def valid_ids_def
                tcb_create_def boot_state_def)

lemma ipc_init_bounded: "bounded (v (cm init_cstate))"
  by (simp add: init_cstate_def init_state_def bounded_def
                max_threads_def tcb_create_def boot_state_def)

lemma ipc_init_integrity: "c_integrity init_cstate"
  by (simp add: init_cstate_def c_integrity_def)

lemma ipc_init_senders: "c_senders_valid init_cstate"
  by (simp add: init_cstate_def c_senders_valid_def nthreads_of_def)

lemma ipc_init_msgs: "c_msgs_ok init_cstate"
  by (simp add: init_cstate_def c_msgs_ok_def msg_ok_def)

lemma ipc_init_noM: "mode (cm init_cstate) \<noteq> MMode"
  by (simp add: init_cstate_def boot_state_def)

(* ---- Preservation: thread-shape invariants ---- *)

lemma ipc_send_valid:
  "valid_ids (v (cm st)) \<Longrightarrow> valid_ids (v (cm (fst (c_send s m st))))"
  unfolding c_send_def runnable_of_def nthreads_of_def
  by (auto simp: suspend_valid resume_valid Let_def
           split: if_split list.split)

lemma ipc_recv_valid:
  "valid_ids (v (cm st)) \<Longrightarrow> valid_ids (v (cm (fst (c_recv r bl st))))"
  unfolding c_recv_def nthreads_of_def
  by (auto simp: suspend_valid resume_valid Let_def
           split: if_split list.split)

lemma ipc_notify_valid:
  "valid_ids (v (cm st)) \<Longrightarrow> valid_ids (v (cm (c_notify t sig st)))"
  by (simp add: c_notify_def resume_valid Let_def split: if_split)

lemma ipc_wait_valid:
  "valid_ids (v (cm st)) \<Longrightarrow> valid_ids (v (cm (fst (c_wait t st))))"
  by (simp add: c_wait_def suspend_valid split: if_split)

lemma ipc_send_bounded:
  "bounded (v (cm st)) \<Longrightarrow> bounded (v (cm (fst (c_send s m st))))"
  unfolding c_send_def runnable_of_def nthreads_of_def
  by (auto simp: suspend_bounded resume_bounded Let_def
           split: if_split list.split)

lemma ipc_recv_bounded:
  "bounded (v (cm st)) \<Longrightarrow> bounded (v (cm (fst (c_recv r bl st))))"
  unfolding c_recv_def nthreads_of_def
  by (auto simp: suspend_bounded resume_bounded Let_def
           split: if_split list.split)

lemma ipc_notify_bounded:
  "bounded (v (cm st)) \<Longrightarrow> bounded (v (cm (c_notify t sig st)))"
  by (simp add: c_notify_def resume_bounded Let_def split: if_split)

lemma ipc_wait_bounded:
  "bounded (v (cm st)) \<Longrightarrow> bounded (v (cm (fst (c_wait t st))))"
  by (simp add: c_wait_def suspend_bounded split: if_split)

(* ---- Preservation: mode never M, kernel writes untouched ---- *)

lemma ipc_send_noM:
  "mode (cm st) \<noteq> MMode \<Longrightarrow> mode (cm (fst (c_send s m st))) \<noteq> MMode"
  unfolding c_send_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_recv_noM:
  "mode (cm st) \<noteq> MMode \<Longrightarrow> mode (cm (fst (c_recv r bl st))) \<noteq> MMode"
  unfolding c_recv_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_notify_noM:
  "mode (cm st) \<noteq> MMode \<Longrightarrow> mode (cm (c_notify t sig st)) \<noteq> MMode"
  by (simp add: c_notify_def Let_def split: if_split)

lemma ipc_wait_noM:
  "mode (cm st) \<noteq> MMode \<Longrightarrow> mode (cm (fst (c_wait t st))) \<noteq> MMode"
  by (simp add: c_wait_def split: if_split)

lemma ipc_send_kw: "kw (cm (fst (c_send s m st))) = kw (cm st)"
  unfolding c_send_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_recv_kw: "kw (cm (fst (c_recv r bl st))) = kw (cm st)"
  unfolding c_recv_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_notify_kw: "kw (cm (c_notify t sig st)) = kw (cm st)"
  by (simp add: c_notify_def Let_def split: if_split)

lemma ipc_wait_kw: "kw (cm (fst (c_wait t st))) = kw (cm st)"
  by (simp add: c_wait_def split: if_split)

(* ---- Preservation: queue bounds ---- *)

lemma ipc_send_qlen:
  "length (sendq (fst (c_send s m st))) \<le> max (length (sendq st)) (max_ipc_q)"
  unfolding c_send_def max_ipc_q_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_recv_qshrinks:
  "length (sendq (fst (c_recv r bl st))) \<le> length (sendq st)"
  unfolding c_recv_def
  by (auto simp: Let_def split: if_split list.split)

(* ---- Preservation: THE integrity theorem (no forge) ---- *)

lemma ipc_send_integrity:
  "c_integrity st \<Longrightarrow> c_integrity (fst (c_send s m st))"
  unfolding c_send_def c_integrity_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_recv_integrity:
  "c_integrity st \<Longrightarrow>
   set (sendq st) \<subseteq> set (sent st) \<Longrightarrow>
   c_integrity (fst (c_recv r bl st))"
  unfolding c_recv_def c_integrity_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_send_queued_subset:
  "set (sendq st) \<subseteq> set (sent st) \<Longrightarrow>
   set (sendq (fst (c_send s m st))) \<subseteq> set (sent (fst (c_send s m st)))"
  unfolding c_send_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_recv_queued_subset:
  "set (sendq st) \<subseteq> set (sent st) \<Longrightarrow>
   set (sendq (fst (c_recv r bl st))) \<subseteq> set (sent (fst (c_recv r bl st)))"
  unfolding c_recv_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_notify_integrity:
  "c_integrity st \<Longrightarrow> c_integrity (c_notify t sig st)"
  by (simp add: c_notify_def c_integrity_def Let_def split: if_split)

lemma ipc_wait_integrity:
  "c_integrity st \<Longrightarrow> c_integrity (fst (c_wait t st))"
  by (simp add: c_wait_def c_integrity_def split: if_split)

(* ---- Preservation: sender ids stay kernel-valid, msgs stay bounded ---- *)

(* C ops never change the thread count (suspend/resume are in-place). *)
lemma ipc_threads_len_suspend:
  "length (threads (tcb_suspend i s)) = length (threads s)"
  by (simp add: tcb_suspend_def split: if_split)

lemma ipc_threads_len_resume:
  "length (threads (tcb_resume i s)) = length (threads s)"
  by (simp add: tcb_resume_def split: if_split)

lemma ipc_send_senders:
  "c_senders_valid st \<Longrightarrow> c_senders_valid (fst (c_send s m st))"
  unfolding c_send_def c_senders_valid_def runnable_of_def nthreads_of_def
  apply (auto simp: Let_def ipc_threads_len_suspend ipc_threads_len_resume
           split: if_split list.split)
  done

lemma ipc_recv_senders:
  "c_senders_valid st \<Longrightarrow>
   set (sendq st) \<subseteq> set (sent st) \<Longrightarrow>
   (\<forall>(s, m) \<in> set (sent st). s < nthreads_of st) \<Longrightarrow>
   c_senders_valid (fst (c_recv r bl st))"
  unfolding c_recv_def c_senders_valid_def nthreads_of_def
  by (auto simp: Let_def ipc_threads_len_suspend ipc_threads_len_resume
           split: if_split list.split)

lemma ipc_send_msgs:
  "c_msgs_ok st \<Longrightarrow> c_msgs_ok (fst (c_send s m st))"
  unfolding c_send_def c_msgs_ok_def msg_ok_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_recv_msgs:
  "c_msgs_ok st \<Longrightarrow> c_msgs_ok (fst (c_recv r bl st))"
  unfolding c_recv_def c_msgs_ok_def
  by (auto simp: Let_def split: if_split list.split)

(* ---- Functional: handoff delivers exactly what was sent ---- *)

lemma ipc_send_handoff:
  "\<lbrakk>msg_ok m; runnable_of st s; length (sendq st) < max_ipc_q;
    recvq st = r # rs\<rbrakk> \<Longrightarrow>
   c_send s m st =
   ((st(|sent := sent st @ [(s, m)], recvq := rs,
         got := got st @ [(s, m)],
         wk := (wk st)(r := 0),
         cm := (cm st)(|v := tcb_resume r (v (cm st))|)|)), True)"
  by (simp add: c_send_def Let_def)

lemma ipc_send_blocks:
  "\<lbrakk>msg_ok m; runnable_of st s; length (sendq st) < max_ipc_q;
    recvq st = []\<rbrakk> \<Longrightarrow>
   c_send s m st =
   ((st(|sent := sent st @ [(s, m)], sendq := sendq st @ [(s, m)],
         wk := (wk st)(s := 1),
         cm := (cm st)(|v := tcb_suspend s (v (cm st))|)|)), True)"
  by (simp add: c_send_def Let_def)

lemma ipc_send_rejects_oversize:
  "\<not> msg_ok m \<Longrightarrow> c_send s m st = (st, False)"
  by (simp add: c_send_def)

lemma ipc_send_rejects_forge:
  "\<not> runnable_of st s \<Longrightarrow> c_send s (m::nat list) st = (st, False)"
  by (simp add: c_send_def msg_ok_def)

lemma ipc_recv_delivers:
  "\<lbrakk>r < nthreads_of st; threads (v (cm st)) ! r = Runnable;
    sendq st = (s, m) # rest\<rbrakk> \<Longrightarrow>
   c_recv r bl st =
   ((st(|sendq := rest,
         got := got st @ [(s, m)],
         wk := (wk st)(s := 0),
         cm := (cm st)(|v := tcb_resume s (v (cm st))|)|)),
    (s, take bl m, length m > bl))"
  by (simp add: c_recv_def Let_def)

lemma ipc_recv_blocks:
  "\<lbrakk>r < nthreads_of st; threads (v (cm st)) ! r = Runnable;
    sendq st = []\<rbrakk> \<Longrightarrow>
   c_recv r bl st =
   ((st(|recvq := recvq st @ [r],
         wk := (wk st)(r := 2),
         cm := (cm st)(|v := tcb_suspend r (v (cm st))|)|)), (0, [], False))"
  by (simp add: c_recv_def Let_def)

(* No silent cut: no-overflow means the full message arrived. *)
lemma ipc_no_silent_cut:
  "\<lbrakk>r < nthreads_of st; threads (v (cm st)) ! r = Runnable;
    sendq st = (s, m) # rest; length m \<le> bl\<rbrakk> \<Longrightarrow>
   snd (c_recv r bl st) = (s, m, False)"
  by (simp add: c_recv_def Let_def)

lemma ipc_trunc_signals:
  "\<lbrakk>r < nthreads_of st; threads (v (cm st)) ! r = Runnable;
    sendq st = (s, m) # rest; length m > bl\<rbrakk> \<Longrightarrow>
   snd (c_recv r bl st) = (s, take bl m, True)"
  by (simp add: c_recv_def Let_def)

(* ---- Functional: notifications ---- *)

lemma ipc_notify_accumulates:
  "t < nthreads_of st \<Longrightarrow>
   ntfy (c_notify t sig st) t = ntfy st t \<union> {sig}"
  by (simp add: c_notify_def nthreads_of_def Let_def split: if_split)

lemma ipc_notify_other_threads:
  "\<lbrakk>t < nthreads_of st; u \<noteq> t\<rbrakk> \<Longrightarrow>
   ntfy (c_notify t sig st) u = ntfy st u"
  by (simp add: c_notify_def nthreads_of_def Let_def split: if_split)

(* NOTIFY wakes a genuine waiter ... *)
lemma ipc_notify_wakes:
  "\<lbrakk>t < nthreads_of st; wk st t = 3\<rbrakk> \<Longrightarrow>
   v (cm (c_notify t sig st)) = tcb_resume t (v (cm st)) \<and>
   wk (c_notify t sig st) t = 0 \<and>
   sig \<in> ntfy (c_notify t sig st) t"
  by (simp add: c_notify_def nthreads_of_def Let_def split: if_split)

(* ... but never disturbs a rendezvous block. *)
lemma ipc_notify_keeps_rendezvous:
  "\<lbrakk>t < nthreads_of st; wk st t \<noteq> 3\<rbrakk> \<Longrightarrow>
   v (cm (c_notify t sig st)) = v (cm st) \<and>
   wk (c_notify t sig st) = wk st \<and>
   sig \<in> ntfy (c_notify t sig st) t"
  by (simp add: c_notify_def nthreads_of_def Let_def split: if_split)

lemma ipc_wait_takes:
  "\<lbrakk>t < nthreads_of st; ntfy st t \<noteq> {}\<rbrakk> \<Longrightarrow>
   c_wait t st = ((st(|ntfy := (ntfy st)(t := {}), wk := (wk st)(t := 0)|)), ntfy st t)"
  by (simp add: c_wait_def Let_def)

lemma ipc_wait_blocks:
  "\<lbrakk>t < nthreads_of st; ntfy st t = {};
    threads (v (cm st)) ! t = Runnable\<rbrakk> \<Longrightarrow>
   fst (c_wait t st) =
   (st(|wk := (wk st)(t := 3),
         cm := (cm st)(|v := tcb_suspend t (v (cm st))|)|)) \<and>
   snd (c_wait t st) = {}"
  by (simp add: c_wait_def Let_def)

(* ---- Mutants: integrity CAN fail; oversize CAN be sent by a mutant ---- *)

definition ipc_mutant_forge :: cstate where
  "ipc_mutant_forge = init_cstate(|got := [(0, [1])]|)"

lemma ipc_mutant_forge_bad: "\<not> c_integrity ipc_mutant_forge"
  by (simp add: ipc_mutant_forge_def init_cstate_def
                c_integrity_def)

definition ipc_mutant_big :: "nat list" where
  "ipc_mutant_big = [0, 1, 2, 3, 4]"

lemma ipc_mutant_big_bad: "\<not> msg_ok ipc_mutant_big"
  by (simp add: ipc_mutant_big_def msg_ok_def max_msg_len_def)

definition ipc_bad_drop :: "nat \<Rightarrow> nat \<Rightarrow> cstate \<Rightarrow> (cstate \<times> (nat \<times> nat list \<times> bool))" where
  "ipc_bad_drop r bl st =
   (case sendq st of
      [] \<Rightarrow> (st, (0, [], False))
    | (s, m) # rest \<Rightarrow> ((st(|sendq := rest|)), (s, take bl m, False)))"

lemma ipc_bad_drop_lies:
  "snd (ipc_bad_drop 1 2
     (init_cstate(|sendq := [(0, [9, 8, 7])], sent := [(0, [9, 8, 7])]|))) =
   (0, [9, 8], False) \<and>
  snd (c_recv 1 2
     (init_cstate(|sendq := [(0, [9, 8, 7])], sent := [(0, [9, 8, 7])]|))) =
   (0, [9, 8], True)"
  by eval

lemma ipc_integrity_nontrivial:
  "(\<exists>st. \<not> c_integrity st) \<and> (\<exists>st. c_integrity st)"
  using ipc_mutant_forge_bad ipc_init_integrity by blast

(* ---- Executable demo: ping-pong between threads 0 and 1 ---- *)

value "let (st1, ok1) = c_send 0 [7, 8] init_cstate;
           (st2, res2) = c_recv 1 4 st1;
           (st3, ok3) = c_send 1 [9] st2;
           (st4, res4) = c_recv 0 4 st3
       in (ok1, res2, ok3, res4, got st4, sent st4)"

lemma ipc_demo_ping:
  "let (st1, ok1) = c_send 0 [7, 8] init_cstate;
       (st2, res2) = c_recv 1 4 st1
   in (ok1, res2, got st2) = (True, (0, [7, 8], False), [(0, [7, 8])])"
  by eval

lemma ipc_demo_pong:
  "let (st1, ok1) = c_send 0 [7, 8] init_cstate;
       (st2, res2) = c_recv 1 4 st1;
       (st3, ok3) = c_send 1 [9] st2;
       (st4, res4) = c_recv 0 4 st3
   in (ok3, res4, got st4) =
      (True, (1, [9], False), [(0, [7, 8]), (1, [9])])"
  by eval

lemma ipc_demo_trunc:
  "let (st1, ok1) = c_send 0 [1, 2, 3] init_cstate;
       (st2, res2) = c_recv 1 2 st1
   in res2 = (0, [1, 2], True)"
  by eval

lemma ipc_demo_notify:
  "let st1 = c_notify 1 3 init_cstate;
       (st2, bits) = c_wait 1 st1
   in (bits, ntfy st2 (1::nat)) = ({3}, {})"
  by eval

lemma ipc_demo_fifo:
  "let init3 = init_cstate(|cm := (cm init_cstate)
                (|v := tcb_create (v (cm init_cstate))|)|);
       (st1, a) = c_send 0 [1] init3;
       (st2, b) = c_send 1 [2] st1;
       (st3, r1) = c_recv 2 4 st2;
       (st4, r2) = c_recv 0 4 st3
   in (a, b, r1, r2) =
      (True, True, (0, [1], False), (1, [2], False))"
  by eval

end
