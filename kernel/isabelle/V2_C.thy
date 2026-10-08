theory V2_C
imports V2_B
begin

(* Moonlight v2, Stage 2: endpoints + notifications, bidirectional IPC.
   Roadmap: docs/V2_DESIGN.md Sec.4 (copy discipline) + Sec.9 Stage 2
   (IPC integrity theorem, ping-pong demo); live-qrexec traffic plan
   (per-EP FIFO, own-EP RECV, guarded SEND).
   Endpoint-indexed queues: one FIFO pair per EP (EP i owned by tid i,
   mirrors kernel/ipc.h V2_NEP = 11 + v2_ep_ok and the kboot eps array).
   SEND carries an explicit destination EP and fails closed on a bad EP;
   RECV carries the caller's EP argument and delivers/suspends only when
   it equals the caller's own EP (the kboot own-EP rule: ep != cur is
   INVALID with no state change). Bounds stay per-EP: max_msg_len = 4,
   max_ipc_q = 16 per EP (matches V2_IPC_Q per v2_ep_t).
   Messages are bounded word lists; sender ids are kernel-stamped, never
   user-supplied.
   Copy discipline (enforced by the implementation, mirrored here by the
   in/out split of the transitions): SEND copies IN, RECV copies OUT,
   CALL would be both (userspace-composed from SEND+RECV until Stage 3
   reply caps exist), NOTIFY/WAIT carry no data.
   Blocking rendezvous (per EP): SEND with no waiter on THAT EP suspends
   the sender and queues (fail-closed when THAT EP is full); RECV with no
   send on its OWN EP suspends the receiver and records the waiter on
   that EP. Delivery appends (sender, full msg) to `got`; every accepted
   send appends to `sent`, so integrity is the subset
   `set got \<subseteq> set sent` (no forge) plus pairing by construction
   (no splice) plus an explicit overflow flag (no silent cut), plus the
   separation theorems (no cross-EP delivery). Notifications are
   per-thread signal sets (OR-accumulate, non-blocking send, blocking
   wait). Zero axioms. *)

definition max_msg_len :: nat where
  "max_msg_len = 4"

definition max_ipc_q :: nat where
  "max_ipc_q = 16"

(* Endpoint count (mirrors V2_NEP; EP i owned by tid i). *)
definition max_eps :: nat where
  "max_eps = 11"

definition msg_ok :: "nat list \<Rightarrow> bool" where
  "msg_ok m = (length m \<le> max_msg_len)"

(* cm = underlying machine (V2_B: modes, console, kw); sendq/recvq =
   per-EP FIFO queues (functions from EP index; empty EP = []);
   sendq i holds queued (sender, msg) pairs for EP i, recvq i holds
   waiting receivers on EP i; sent = every accepted send (monotone
   history); got = every delivery; ntfy = per-thread pending signal
   sets; wk = per-thread wait kind (0 none, 1 send-blocked,
   2 recv-blocked, 3 wait-blocked) so NOTIFY wakes only genuine waiters,
   never a thread blocked in rendezvous. *)

record cstate =
  cm :: mstate
  sendq :: "nat \<Rightarrow> (nat \<times> nat list) list"
  recvq :: "nat \<Rightarrow> nat list"
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
     sendq = (\<lambda>_. []), recvq = (\<lambda>_. []),
     sent = [], got = [],
     ntfy = (\<lambda>_. {}), wk = (\<lambda>_. 0)|)"

(* ---- Transitions (total: bad id/EP/length/full queue/non-runnable are
   no-ops or error returns, never undefined) ---- *)

(* SEND s dst m: gate the destination EP (fail closed), accept (record in
   sent) and either hand off to the oldest waiter OF THAT EP (resume it)
   or queue on that EP + suspend the sender. Returns ok flag. *)
definition c_send :: "nat \<Rightarrow> nat \<Rightarrow> nat list \<Rightarrow> cstate \<Rightarrow> (cstate \<times> bool)" where
  "c_send s dst m st =
   (if max_eps \<le> dst \<or> \<not> msg_ok m \<or> \<not> runnable_of st s \<or> length (sendq st dst) \<ge> max_ipc_q
    then (st, False)
    else let st1 = st(|sent := sent st @ [(s, m)]|) in
    case recvq st dst of
      [] \<Rightarrow> ((st1(|sendq := (sendq st1)(dst := sendq st1 dst @ [(s, m)]),
                 wk := (wk st1)(s := 1),
                 cm := (cm st)(|v := tcb_suspend s (v (cm st))|)|)), True)
    | r # rs \<Rightarrow> ((st1(|recvq := (recvq st1)(dst := rs),
                 got := got st @ [(s, m)],
                 wk := (wk st1)(r := 0),
                 cm := (cm st)(|v := tcb_resume r (v (cm st))|)|)), True))"

(* RECV r own bl: the own-EP rule comes FIRST (fail closed with no state
   change, mirroring the kboot ep != cur INVALID return). Then deliver
   the oldest queued send OF THAT EP (resume the sender, truncate to bl
   with an explicit overflow flag) or record the waiter on that EP +
   suspend. Returns (sender, delivered, overflow); (0, [], True) is the
   error shape (foreign EP / bad EP / bad id / non-runnable), distinct
   from blocking (False flag, empty delivery). *)
definition c_recv :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> cstate \<Rightarrow> (cstate \<times> (nat \<times> nat list \<times> bool))" where
  "c_recv r own bl st =
   (if own \<noteq> r \<or> max_eps \<le> own \<or> r \<ge> nthreads_of st \<or> threads (v (cm st)) ! r \<noteq> Runnable
    then (st, (0, [], True))
    else case sendq st own of
      [] \<Rightarrow> ((st(|recvq := (recvq st)(own := recvq st own @ [r]),
                 wk := (wk st)(r := 2),
                 cm := (cm st)(|v := tcb_suspend r (v (cm st))|)|)), (0, [], False))
    | (s, m) # rest \<Rightarrow>
        let dlv = take bl m; ovf = (length m > bl) in
        ((st(|sendq := (sendq st)(own := rest),
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
   ((\<forall>i<max_eps. \<forall>(s, m) \<in> set (sendq st i). s < nthreads_of st) \<and>
    (\<forall>(s, m) \<in> set (got st). s < nthreads_of st))"

definition c_msgs_ok :: "cstate \<Rightarrow> bool" where
  "c_msgs_ok st =
   ((\<forall>i<max_eps. \<forall>(s, m) \<in> set (sendq st i). msg_ok m) \<and>
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
  "valid_ids (v (cm st)) \<Longrightarrow> valid_ids (v (cm (fst (c_send s dst m st))))"
  unfolding c_send_def runnable_of_def nthreads_of_def
  by (auto simp: suspend_valid resume_valid Let_def
           split: if_split list.split)

lemma ipc_recv_valid:
  "valid_ids (v (cm st)) \<Longrightarrow> valid_ids (v (cm (fst (c_recv r own bl st))))"
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
  "bounded (v (cm st)) \<Longrightarrow> bounded (v (cm (fst (c_send s dst m st))))"
  unfolding c_send_def runnable_of_def nthreads_of_def
  by (auto simp: suspend_bounded resume_bounded Let_def
           split: if_split list.split)

lemma ipc_recv_bounded:
  "bounded (v (cm st)) \<Longrightarrow> bounded (v (cm (fst (c_recv r own bl st))))"
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
  "mode (cm st) \<noteq> MMode \<Longrightarrow> mode (cm (fst (c_send s dst m st))) \<noteq> MMode"
  unfolding c_send_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_recv_noM:
  "mode (cm st) \<noteq> MMode \<Longrightarrow> mode (cm (fst (c_recv r own bl st))) \<noteq> MMode"
  unfolding c_recv_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_notify_noM:
  "mode (cm st) \<noteq> MMode \<Longrightarrow> mode (cm (c_notify t sig st)) \<noteq> MMode"
  by (simp add: c_notify_def Let_def split: if_split)

lemma ipc_wait_noM:
  "mode (cm st) \<noteq> MMode \<Longrightarrow> mode (cm (fst (c_wait t st))) \<noteq> MMode"
  by (simp add: c_wait_def split: if_split)

lemma ipc_send_kw: "kw (cm (fst (c_send s dst m st))) = kw (cm st)"
  unfolding c_send_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_recv_kw: "kw (cm (fst (c_recv r own bl st))) = kw (cm st)"
  unfolding c_recv_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_notify_kw: "kw (cm (c_notify t sig st)) = kw (cm st)"
  by (simp add: c_notify_def Let_def split: if_split)

lemma ipc_wait_kw: "kw (cm (fst (c_wait t st))) = kw (cm st)"
  by (simp add: c_wait_def split: if_split)

(* ---- Preservation: per-EP queue bounds ---- *)

lemma ipc_send_qlen:
  "length (sendq (fst (c_send s dst m st)) dst) \<le> max (length (sendq st dst)) max_ipc_q"
  unfolding c_send_def max_ipc_q_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_recv_qshrinks:
  "length (sendq (fst (c_recv r own bl st)) own) \<le> length (sendq st own)"
  unfolding c_recv_def
  by (auto simp: Let_def split: if_split list.split)

(* ---- Preservation: THE integrity theorem (no forge) ---- *)

lemma ipc_send_integrity:
  "c_integrity st \<Longrightarrow> c_integrity (fst (c_send s dst m st))"
  unfolding c_send_def c_integrity_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_recv_integrity:
  "c_integrity st \<Longrightarrow>
   set (sendq st own) \<subseteq> set (sent st) \<Longrightarrow>
   c_integrity (fst (c_recv r own bl st))"
  unfolding c_recv_def c_integrity_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_send_queued_subset:
  "set (sendq st j) \<subseteq> set (sent st) \<Longrightarrow>
   set (sendq (fst (c_send s dst m st)) j) \<subseteq> set (sent (fst (c_send s dst m st)))"
  unfolding c_send_def
  by (auto simp: Let_def split: if_split list.split)

lemma ipc_recv_queued_subset:
  "set (sendq st j) \<subseteq> set (sent st) \<Longrightarrow>
   set (sendq (fst (c_recv r own bl st)) j) \<subseteq> set (sent (fst (c_recv r own bl st)))"
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
  "c_senders_valid st \<Longrightarrow> c_senders_valid (fst (c_send s dst m st))"
proof -
  assume h: "c_senders_valid st"
  have ep: "\<And>i a b. i < max_eps \<Longrightarrow> (a, b) \<in> set (sendq st i) \<Longrightarrow>
                     a < length (threads (v (cm st)))"
    using h unfolding c_senders_valid_def nthreads_of_def by blast
  have gotv: "\<And>a b. (a, b) \<in> set (got st) \<Longrightarrow> a < length (threads (v (cm st)))"
    using h unfolding c_senders_valid_def nthreads_of_def by blast
  have epraw: "\<And>i a b. \<lbrakk>\<not> max_eps \<le> i; (a, b) \<in> set (sendq st i)\<rbrakk> \<Longrightarrow>
                        a < length (threads (v (cm st)))"
  proof -
    fix i a b
    assume nb: "\<not> max_eps \<le> i" and mem: "(a, b) \<in> set (sendq st i)"
    have lt: "i < max_eps" using nb by simp
    show "a < length (threads (v (cm st)))" using lt mem ep by blast
  qed
  show ?thesis
    unfolding c_send_def c_senders_valid_def runnable_of_def nthreads_of_def
    apply (auto simp: Let_def ipc_threads_len_suspend ipc_threads_len_resume
             intro: ep epraw gotv split: if_split list.split)
    done
qed

lemma ipc_recv_senders:
  "c_senders_valid st \<Longrightarrow>
   set (sendq st own) \<subseteq> set (sent st) \<Longrightarrow>
   (\<forall>(s, m) \<in> set (sent st). s < nthreads_of st) \<Longrightarrow>
   c_senders_valid (fst (c_recv r own bl st))"
proof -
  assume h: "c_senders_valid st"
  have ep: "\<And>i a b. i < max_eps \<Longrightarrow> (a, b) \<in> set (sendq st i) \<Longrightarrow>
                     a < length (threads (v (cm st)))"
    using h unfolding c_senders_valid_def nthreads_of_def by blast
  have gotv: "\<And>a b. (a, b) \<in> set (got st) \<Longrightarrow> a < length (threads (v (cm st)))"
    using h unfolding c_senders_valid_def nthreads_of_def by blast
  have tailmem: "\<And>i a b rr s' m'. \<lbrakk>(a, b) \<in> set rr; sendq st i = (s', m') # rr\<rbrakk> \<Longrightarrow>
                                         (a, b) \<in> set (sendq st i)"
    by simp
  have headmem: "\<And>i s' m' rr. \<lbrakk>sendq st i = (s', m') # rr; \<not> max_eps \<le> i\<rbrakk> \<Longrightarrow>
                                    s' < length (threads (v (cm st)))"
  proof -
    fix i s' m' rr
    assume eq: "sendq st i = (s', m') # rr" and nb: "\<not> max_eps \<le> i"
    have mem: "(s', m') \<in> set (sendq st i)" using eq by simp
    have lt: "i < max_eps" using nb by simp
    show "s' < length (threads (v (cm st)))" using lt mem ep by blast
  qed
  have epraw: "\<And>i a b. \<lbrakk>\<not> max_eps \<le> i; (a, b) \<in> set (sendq st i)\<rbrakk> \<Longrightarrow>
                        a < length (threads (v (cm st)))"
  proof -
    fix i a b
    assume nb: "\<not> max_eps \<le> i" and mem: "(a, b) \<in> set (sendq st i)"
    have lt: "i < max_eps" using nb by simp
    show "a < length (threads (v (cm st)))" using lt mem ep by blast
  qed
  have ep2raw: "\<And>i a b rr s' m'. \<lbrakk>\<not> max_eps \<le> i; (a, b) \<in> set rr;
                                        sendq st i = (s', m') # rr\<rbrakk> \<Longrightarrow>
                                         a < length (threads (v (cm st)))"
  proof -
    fix i a b rr s' m'
    assume nb: "\<not> max_eps \<le> i" and memrr: "(a, b) \<in> set rr"
       and eq: "sendq st i = (s', m') # rr"
    have mem: "(a, b) \<in> set (sendq st i)" using memrr eq by simp
    have lt: "i < max_eps" using nb by simp
    show "a < length (threads (v (cm st)))" using lt mem ep by blast
  qed
  show ?thesis
    unfolding c_recv_def c_senders_valid_def nthreads_of_def
    apply (auto simp: Let_def ipc_threads_len_suspend ipc_threads_len_resume
             intro: ep epraw ep2raw tailmem headmem gotv split: if_split list.split)
    done
qed

lemma ipc_send_msgs:
  "c_msgs_ok st \<Longrightarrow> c_msgs_ok (fst (c_send s dst m st))"
proof -
  assume h: "c_msgs_ok st"
  have mep: "\<And>i a b. i < max_eps \<Longrightarrow> (a, b) \<in> set (sendq st i) \<Longrightarrow>
                      length b \<le> max_msg_len"
    using h unfolding c_msgs_ok_def msg_ok_def by blast
  have gotm: "\<And>a b. (a, b) \<in> set (got st) \<Longrightarrow> length b \<le> max_msg_len"
    using h unfolding c_msgs_ok_def msg_ok_def by blast
  have sentm: "\<And>a b. (a, b) \<in> set (sent st) \<Longrightarrow> length b \<le> max_msg_len"
    using h unfolding c_msgs_ok_def msg_ok_def by blast
  have mepraw: "\<And>i a b. \<lbrakk>\<not> max_eps \<le> i; (a, b) \<in> set (sendq st i)\<rbrakk> \<Longrightarrow>
                         length b \<le> max_msg_len"
  proof -
    fix i a b
    assume nb: "\<not> max_eps \<le> i" and mem: "(a, b) \<in> set (sendq st i)"
    have lt: "i < max_eps" using nb by simp
    show "length b \<le> max_msg_len" using lt mem mep by blast
  qed
  show ?thesis
    unfolding c_send_def c_msgs_ok_def msg_ok_def
    apply (auto simp: Let_def intro: mep mepraw gotm sentm split: if_split list.split)
    done
qed

lemma ipc_recv_msgs:
  "c_msgs_ok st \<Longrightarrow> c_msgs_ok (fst (c_recv r own bl st))"
proof -
  assume h: "c_msgs_ok st"
  have mep: "\<And>i a b. i < max_eps \<Longrightarrow> (a, b) \<in> set (sendq st i) \<Longrightarrow>
                      length b \<le> max_msg_len"
    using h unfolding c_msgs_ok_def msg_ok_def by blast
  have gotm: "\<And>a b. (a, b) \<in> set (got st) \<Longrightarrow> length b \<le> max_msg_len"
    using h unfolding c_msgs_ok_def msg_ok_def by blast
  have sentm: "\<And>a b. (a, b) \<in> set (sent st) \<Longrightarrow> length b \<le> max_msg_len"
    using h unfolding c_msgs_ok_def msg_ok_def by blast
  have tailmem: "\<And>i a b rr s' m'. \<lbrakk>(a, b) \<in> set rr; sendq st i = (s', m') # rr\<rbrakk> \<Longrightarrow>
                                         (a, b) \<in> set (sendq st i)"
    by simp
  have headmem2: "\<And>i s' m' rr. \<lbrakk>sendq st i = (s', m') # rr; \<not> max_eps \<le> i\<rbrakk> \<Longrightarrow>
                                     length m' \<le> max_msg_len"
  proof -
    fix i s' m' rr
    assume eq: "sendq st i = (s', m') # rr" and nb: "\<not> max_eps \<le> i"
    have mem: "(s', m') \<in> set (sendq st i)" using eq by simp
    have lt: "i < max_eps" using nb by simp
    show "length m' \<le> max_msg_len" using lt mem mep by blast
  qed
  have mepraw: "\<And>i a b. \<lbrakk>\<not> max_eps \<le> i; (a, b) \<in> set (sendq st i)\<rbrakk> \<Longrightarrow>
                         length b \<le> max_msg_len"
  proof -
    fix i a b
    assume nb: "\<not> max_eps \<le> i" and mem: "(a, b) \<in> set (sendq st i)"
    have lt: "i < max_eps" using nb by simp
    show "length b \<le> max_msg_len" using lt mem mep by blast
  qed
  have mep2: "\<And>i a b rr s' m'. \<lbrakk>i < max_eps; (a, b) \<in> set rr;
                                      sendq st i = (s', m') # rr\<rbrakk> \<Longrightarrow>
                                       length b \<le> max_msg_len"
  proof -
    fix i a b rr s' m'
    assume ii: "i < max_eps" and memrr: "(a, b) \<in> set rr"
       and eq: "sendq st i = (s', m') # rr"
    have mem: "(a, b) \<in> set (sendq st i)" using memrr eq by simp
    show "length b \<le> max_msg_len" using ii mem mep by blast
  qed
  have mep2raw: "\<And>i a b rr s' m'. \<lbrakk>\<not> max_eps \<le> i; (a, b) \<in> set rr;
                                          sendq st i = (s', m') # rr\<rbrakk> \<Longrightarrow>
                                           length b \<le> max_msg_len"
  proof -
    fix i a b rr s' m'
    assume nb: "\<not> max_eps \<le> i" and memrr: "(a, b) \<in> set rr"
       and eq: "sendq st i = (s', m') # rr"
    have mem: "(a, b) \<in> set (sendq st i)" using memrr eq by simp
    have lt: "i < max_eps" using nb by simp
    show "length b \<le> max_msg_len" using lt mem mep by blast
  qed
  show ?thesis
    unfolding c_recv_def c_msgs_ok_def msg_ok_def
    apply (auto simp: Let_def intro: mep mepraw mep2 mep2raw headmem2 gotm sentm tailmem
             split: if_split list.split)
    done
qed

(* ---- Functional: handoff delivers exactly what was sent (per EP) ---- *)

lemma ipc_send_handoff:
  "\<lbrakk>msg_ok m; runnable_of st s; dst < max_eps; length (sendq st dst) < max_ipc_q;
    recvq st dst = r # rs\<rbrakk> \<Longrightarrow>
   c_send s dst m st =
   ((st(|sent := sent st @ [(s, m)], recvq := (recvq st)(dst := rs),
         got := got st @ [(s, m)],
         wk := (wk st)(r := 0),
         cm := (cm st)(|v := tcb_resume r (v (cm st))|)|)), True)"
  by (simp add: c_send_def Let_def)

lemma ipc_send_blocks:
  "\<lbrakk>msg_ok m; runnable_of st s; dst < max_eps; length (sendq st dst) < max_ipc_q;
    recvq st dst = []\<rbrakk> \<Longrightarrow>
   c_send s dst m st =
   ((st(|sent := sent st @ [(s, m)], sendq := (sendq st)(dst := sendq st dst @ [(s, m)]),
         wk := (wk st)(s := 1),
         cm := (cm st)(|v := tcb_suspend s (v (cm st))|)|)), True)"
  by (simp add: c_send_def Let_def)

lemma ipc_send_rejects_oversize:
  "\<not> msg_ok m \<Longrightarrow> c_send s dst m st = (st, False)"
  by (simp add: c_send_def)

lemma ipc_send_rejects_forge:
  "\<not> runnable_of st s \<Longrightarrow> c_send s dst (m::nat list) st = (st, False)"
  by (simp add: c_send_def msg_ok_def)

(* Bad destination EP: fail closed, state unchanged (v2_ep_ok gate). *)
lemma ipc_send_bad_ep:
  "max_eps \<le> dst \<Longrightarrow> c_send s dst m st = (st, False)"
  by (simp add: c_send_def)

lemma ipc_recv_delivers:
  "\<lbrakk>r < nthreads_of st; threads (v (cm st)) ! r = Runnable;
    own = r; own < max_eps;
    sendq st own = (s, m) # rest\<rbrakk> \<Longrightarrow>
   c_recv r own bl st =
   ((st(|sendq := (sendq st)(own := rest),
         got := got st @ [(s, m)],
         wk := (wk st)(s := 0),
         cm := (cm st)(|v := tcb_resume s (v (cm st))|)|)),
    (s, take bl m, length m > bl))"
  by (simp add: c_recv_def Let_def)

lemma ipc_recv_blocks:
  "\<lbrakk>r < nthreads_of st; threads (v (cm st)) ! r = Runnable;
    own = r; own < max_eps;
    sendq st own = []\<rbrakk> \<Longrightarrow>
   c_recv r own bl st =
   ((st(|recvq := (recvq st)(own := recvq st own @ [r]),
         wk := (wk st)(r := 2),
         cm := (cm st)(|v := tcb_suspend r (v (cm st))|)|)), (0, [], False))"
  by (simp add: c_recv_def Let_def)

(* Foreign EP: the own-EP rule fails closed with no state change. *)
lemma ipc_recv_foreign_noop:
  "own \<noteq> r \<Longrightarrow> c_recv r own bl st = (st, (0, [], True))"
  by (simp add: c_recv_def)

(* Bad EP index: fail closed with no state change. *)
lemma ipc_recv_bad_ep_noop:
  "max_eps \<le> own \<Longrightarrow> c_recv r own bl st = (st, (0, [], True))"
  by (simp add: c_recv_def)

(* No silent cut: no-overflow means the full message arrived. *)
lemma ipc_no_silent_cut:
  "\<lbrakk>r < nthreads_of st; threads (v (cm st)) ! r = Runnable;
    own = r; own < max_eps;
    sendq st own = (s, m) # rest; length m \<le> bl\<rbrakk> \<Longrightarrow>
   snd (c_recv r own bl st) = (s, m, False)"
  by (simp add: c_recv_def Let_def)

lemma ipc_trunc_signals:
  "\<lbrakk>r < nthreads_of st; threads (v (cm st)) ! r = Runnable;
    own = r; own < max_eps;
    sendq st own = (s, m) # rest; length m > bl\<rbrakk> \<Longrightarrow>
   snd (c_recv r own bl st) = (s, take bl m, True)"
  by (simp add: c_recv_def Let_def)

(* ---- Separation: ops on EP i leave every EP j\<noteq>i bit-identical ---- *)

lemma ep_separation_send:
  "j \<noteq> dst \<Longrightarrow>
   sendq (fst (c_send s dst m st)) j = sendq st j \<and>
   recvq (fst (c_send s dst m st)) j = recvq st j"
  unfolding c_send_def
  by (auto simp: Let_def split: if_split list.split)

lemma ep_separation_recv:
  "j \<noteq> own \<Longrightarrow>
   sendq (fst (c_recv r own bl st)) j = sendq st j \<and>
   recvq (fst (c_recv r own bl st)) j = recvq st j"
  unfolding c_recv_def
  by (auto simp: Let_def split: if_split list.split)

lemma ep_separation:
  "(j \<noteq> dst \<longrightarrow> sendq (fst (c_send s dst m st)) j = sendq st j \<and>
                  recvq (fst (c_send s dst m st)) j = recvq st j) \<and>
   (j \<noteq> own \<longrightarrow> sendq (fst (c_recv r own bl st)) j = sendq st j \<and>
                  recvq (fst (c_recv r own bl st)) j = recvq st j)"
  using ep_separation_send ep_separation_recv by blast

(* NOTIFY/WAIT never touch any endpoint queue. *)
lemma ipc_notify_eps:
  "sendq (c_notify t sig st) = sendq st \<and> recvq (c_notify t sig st) = recvq st"
  by (simp add: c_notify_def Let_def split: if_split)

lemma ipc_wait_eps:
  "sendq (fst (c_wait t st)) = sendq st \<and> recvq (fst (c_wait t st)) = recvq st"
  by (simp add: c_wait_def split: if_split)

(* ---- No cross-EP delivery: RECV on EP `own` returns only EP-`own`
   bytes (or a no-delivery shape) ---- *)

lemma no_cross_deliver:
  assumes h: "snd (c_recv r own bl st) = (s, dlv, ovf)"
  shows "(s, dlv, ovf) = (0, [], True) \<or> (s, dlv, ovf) = (0, [], False) \<or>
    (\<exists>m. (s, m) \<in> set (sendq st own) \<and> dlv = take bl m \<and> ovf = (length m > bl))"
proof (cases "own \<noteq> r \<or> max_eps \<le> own \<or> r \<ge> nthreads_of st \<or>
              threads (v (cm st)) ! r \<noteq> Runnable")
  case True
  then have e: "c_recv r own bl st = (st, (0, [], True))"
    by (simp add: c_recv_def)
  show ?thesis using h e by simp
next
  case False
  hence nr: "own = r" and nb: "own < max_eps" and
        nt: "r < nthreads_of st" and rn: "threads (v (cm st)) ! r = Runnable"
    by auto
  show ?thesis
  proof (cases "sendq st own")
    case Nil
    hence e: "c_recv r own bl st =
      ((st(|recvq := (recvq st)(own := recvq st own @ [r]),
            wk := (wk st)(r := 2),
            cm := (cm st)(|v := tcb_suspend r (v (cm st))|)|)), (0, [], False))"
      using nr nb nt rn by (simp add: c_recv_def)
    show ?thesis using h e by simp
  next
    case (Cons a rest)
    obtain s' m' where a: "a = (s', m')" by (cases a) simp
    have e: "snd (c_recv r own bl st) = (s', take bl m', length m' > bl)"
      using nr nb nt rn Cons a by (simp add: c_recv_def Let_def)
    have m: "(s', m') \<in> set (sendq st own)" using Cons a by simp
    have eq: "(s, dlv, ovf) = (s', take bl m', length m' > bl)"
      using h e by simp
    show ?thesis
      apply (rule disjI2)
      apply (rule disjI2)
      apply (rule exI[of _ m'])
      using eq m by simp
  qed
qed

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

definition ipc_bad_drop :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> cstate \<Rightarrow> (cstate \<times> (nat \<times> nat list \<times> bool))" where
  "ipc_bad_drop r own bl st =
   (case sendq st own of
      [] \<Rightarrow> (st, (0, [], False))
    | (s, m) # rest \<Rightarrow> ((st(|sendq := (sendq st)(own := rest)|)), (s, take bl m, False)))"

lemma ipc_bad_drop_lies:
  "snd (ipc_bad_drop 1 1 2
     (init_cstate(|sendq := (sendq init_cstate)(1 := [(0, [9, 8, 7])]),
                   sent := [(0, [9, 8, 7])]|))) =
   (0, [9, 8], False) \<and>
  snd (c_recv 1 1 2
     (init_cstate(|sendq := (sendq init_cstate)(1 := [(0, [9, 8, 7])]),
                   sent := [(0, [9, 8, 7])]|))) =
   (0, [9, 8], True)"
  by eval

lemma ipc_integrity_nontrivial:
  "(\<exists>st. \<not> c_integrity st) \<and> (\<exists>st. c_integrity st)"
  using ipc_mutant_forge_bad ipc_init_integrity by blast

(* ---- Mutants: separation CAN be violated (snoop + guard-drop) ---- *)

(* Snoop mutant op: serves another EP's bytes to this receiver,
   violating no_cross_deliver. *)
definition ipc_bad_snoop :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> cstate \<Rightarrow> (cstate \<times> (nat \<times> nat list \<times> bool))" where
  "ipc_bad_snoop r wrong bl st =
   (case sendq st wrong of
      [] \<Rightarrow> (st, (0, [], False))
    | (s, m) # rest \<Rightarrow>
        ((st(|sendq := (sendq st)(wrong := rest)|)), (s, take bl m, length m > bl)))"

(* Guard-drop mutant op: ignores the EP argument and always serves the
   caller's own EP, violating the foreign noop. *)
definition ipc_bad_noguard :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> cstate \<Rightarrow> (cstate \<times> (nat \<times> nat list \<times> bool))" where
  "ipc_bad_noguard r own bl st = c_recv r r bl st"

(* Six-thread init scaffold for the EP3/EP5 snoop pins (small constants;
   threads 0..5 all Runnable). *)
definition init6 :: cstate where
  "init6 = init_cstate(|cm := (cm init_cstate)
    (|v := tcb_create (tcb_create (tcb_create (tcb_create (v (cm init_cstate)))))|)|)"

(* The snoop mutant serves EP3's bytes to an EP5 receiver while the real
   op returns none: no_cross_deliver is falsifiable. *)
lemma ipc_bad_snoop_differs:
  "let (st1, ok1) = c_send 0 3 [7, 8] init6 in
   (ok1, snd (ipc_bad_snoop 5 3 4 st1), snd (c_recv 5 5 4 st1)) =
   (True, (0, [7, 8], False), (0, [], False))"
  by eval

(* The guard-drop mutant answers a foreign call while the real op fails
   closed: the own-EP rule is observable. *)
lemma ipc_bad_noguard_differs:
  "let (st1, ok1) = c_send 0 0 [7, 8] init_cstate in
   (ok1, snd (c_recv 1 0 4 st1), snd (ipc_bad_noguard 1 0 4 st1)) =
   (True, (0, [], True), (0, [], False))"
  by eval

(* ---- Executable demo: ping-pong between threads 0 and 1 over EPs ---- *)

value "let (st1, ok1) = c_send 0 1 [7, 8] init_cstate;
           (st2, res2) = c_recv 1 1 4 st1;
           (st3, ok3) = c_send 1 0 [9] st2;
           (st4, res4) = c_recv 0 0 4 st3
       in (ok1, res2, ok3, res4, got st4, sent st4)"

lemma ipc_demo_ping:
  "let (st1, ok1) = c_send 0 1 [7, 8] init_cstate;
       (st2, res2) = c_recv 1 1 4 st1
   in (ok1, res2, got st2) = (True, (0, [7, 8], False), [(0, [7, 8])])"
  by eval

lemma ipc_demo_pong:
  "let (st1, ok1) = c_send 0 1 [7, 8] init_cstate;
       (st2, res2) = c_recv 1 1 4 st1;
       (st3, ok3) = c_send 1 0 [9] st2;
       (st4, res4) = c_recv 0 0 4 st3
   in (ok1, ok3, res4, got st4) =
      (True, True, (1, [9], False), [(0, [7, 8]), (1, [9])])"
  by eval

lemma ipc_demo_trunc:
  "let (st1, ok1) = c_send 0 1 [1, 2, 3] init_cstate;
       (st2, res2) = c_recv 1 1 2 st1
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
       (st1, a) = c_send 0 2 [1] init3;
       (st2, b) = c_send 1 2 [2] st1;
       (st3, r1) = c_recv 2 2 4 st2;
       (st4, r2) = c_recv 2 2 4 st3
   in (a, b, r1, r2) =
      (True, True, (0, [1], False), (1, [2], False))"
  by eval

(* ---- Executable pins: separation (same-EP round-trip, cross-EP
   invisibility, per-EP full queue) + foreign noop ---- *)

(* Same-EP round-trip: thread 0 sends to EP1, thread 1 receives EP1.
   Distinct payload from ipc_demo_ping above (both pin the shape). *)
lemma ipc_demo_same_ep:
  "let (st1, ok1) = c_send 0 1 [5] init_cstate;
       (st2, res2) = c_recv 1 1 4 st1
   in (ok1, res2, got st2) = (True, (0, [5], False), [(0, [5])])"
  by eval

(* Cross-EP invisibility: bytes queued on EP3 are invisible to a RECV on
   EP5 (blocks with none), and the EP3 queue is bit-identical after. *)
lemma ipc_demo_snoop:
  "let (st1, ok1) = c_send 0 3 [7, 8] init6;
       (st2, res2) = c_recv 5 5 4 st1
   in (ok1, res2, sendq st2 3, sendq st2 5) =
      (True, (0, [], False), [(0, [7, 8])], [])"
  by eval

(* Foreign call: RECV with own \<noteq> caller fails closed with the error
   shape and leaves every projected queue/history bit-identical. *)
lemma ipc_demo_foreign:
  "(snd (c_recv 1 5 4 init_cstate),
    sendq (fst (c_recv 1 5 4 init_cstate)) 3,
    recvq (fst (c_recv 1 5 4 init_cstate)) 5,
    got (fst (c_recv 1 5 4 init_cstate)),
    sent (fst (c_recv 1 5 4 init_cstate))) =
   ((0, [], True), [], [], [], [])"
  by eval

(* Queue-full on one EP leaves the others working: EP0 full rejects,
   EP1 accepts, lengths pinned. *)
lemma ipc_demo_full_isolated:
  "let full0 = init_cstate(|sendq := (sendq init_cstate)(0 := replicate 16 (0, [1])),
                            sent := replicate 16 (0, [1])|);
       (stF, okF) = c_send 0 0 [2] full0;
       (st1, ok1) = c_send 0 1 [2] full0
   in (okF, ok1, length (sendq stF 0), length (sendq st1 1)) =
      (False, True, 16, 1)"
  by eval

(* ---- Executable pins: notify take-and-clear + WAIT re-blocks (UABI
   wake-delivery KAT: WAIT takes pending signals into regs[10] and
   clears them, so a second WAIT with nothing pending suspends) ---- *)

(* WAIT takes pending signals and clears them (wk back to 0). *)
lemma ipc_demo_notify_take_clears:
  "let st1 = c_notify 1 3 init_cstate;
       (st2, bits) = c_wait 1 st1
   in (bits, ntfy st2 (1::nat), wk st2 (1::nat)) = ({3}, {}, 0)"
  by eval

(* A second WAIT with nothing pending suspends again (wk = 3, no bits). *)
lemma ipc_demo_wait_reblocks:
  "let st1 = c_notify 1 3 init_cstate;
       (st2, bits) = c_wait 1 st1;
       (st3, bits2) = c_wait 1 st2
   in (bits, bits2, wk st3 (1::nat)) = ({3}, {}, 3)"
  by eval

(* ---- S4a replay pins: EP10 (gui tid 10) fits the bumped bound ---- *)

(* EP10 is a valid destination under max_eps = 11 (S4a gui EP10). *)
lemma ipc_gui_ep_fits:
  "10 < max_eps"
  by (simp add: max_eps_def)

(* EP11 is out of range: SEND fails closed with no state change. *)
lemma ipc_send_ep11_rejects:
  "c_send s 11 m st = (st, False)"
  by (simp add: c_send_def max_eps_def)

(* ---- S4b compositor pins (gui server on EP10, server-owned surfaces) ----
   Shipped C values, verbatim (userspace/gui/v2_main.c + surf.h, 40x30):
   FILL tag 6 (S4a direct/surface fill), SURF_CREATE 7, SURF_DESTROY 8,
   COMPOSE 9; replies R_OK 0 / R_DENY -1 (call/response discipline, one
   reply per RPC); 4 server-owned surfaces of 40x30 px; 20px server-painted
   chrome strip (direct-path y < 20 DENYed, COMPOSE repaints chrome).
   There is no message datatype / FILL case to clone here: the model sends
   raw nat lists, so deliveries⊆sends (c_integrity) + no_cross_deliver
   already quantify over ALL payloads and the new tags inherit them by
   instantiation (instance lemmas below pin exactly that). max_eps is
   UNCHANGED (no-bump). Zero axioms. *)

definition gui_fill_tag :: nat where
  "gui_fill_tag = 6"

definition gui_surf_create_tag :: nat where
  "gui_surf_create_tag = 7"

definition gui_surf_destroy_tag :: nat where
  "gui_surf_destroy_tag = 8"

definition gui_compose_tag :: nat where
  "gui_compose_tag = 9"

definition gui_surf_n :: nat where
  "gui_surf_n = 4"

definition gui_surf_w :: nat where
  "gui_surf_w = 40"

definition gui_surf_h :: nat where
  "gui_surf_h = 30"

definition gui_chrome_h :: nat where
  "gui_chrome_h = 20"

(* Tags pairwise distinct (new tags distinct from each other and from FILL). *)
lemma gui_tags_distinct:
  "gui_surf_create_tag \<noteq> gui_surf_destroy_tag \<and>
   gui_surf_create_tag \<noteq> gui_compose_tag \<and>
   gui_surf_destroy_tag \<noteq> gui_compose_tag \<and>
   gui_fill_tag \<noteq> gui_surf_create_tag \<and>
   gui_fill_tag \<noteq> gui_surf_destroy_tag \<and>
   gui_fill_tag \<noteq> gui_compose_tag"
  by (simp add: gui_fill_tag_def gui_surf_create_tag_def
                gui_surf_destroy_tag_def gui_compose_tag_def)

(* No-bump pin: the S4b RPC set rides the S4a bound unchanged. *)
lemma max_eps_s4b_unchanged:
  "max_eps = 11"
  by (simp add: max_eps_def)

(* Pilot legs fit the shipped surfaces (CREATE wh = 40x30; FILL 20x10 at
   (5,5): 5+20 \<le> 40, 5+10 \<le> 30). *)
lemma gui_pilot_legs_fit:
  "gui_surf_w = 40 \<and> gui_surf_h = 30 \<and>
   5 + 20 \<le> gui_surf_w \<and> 5 + 10 \<le> gui_surf_h"
  by (simp add: gui_surf_w_def gui_surf_h_def)

(* All three S4b RPC shapes satisfy the bounded-message gate. *)
lemma ipc_s4b_shapes_msg_ok:
  "msg_ok [gui_surf_create_tag, sid, wh, fl] \<and>
   msg_ok [gui_surf_destroy_tag, sid] \<and>
   msg_ok [gui_compose_tag]"
  by (simp add: msg_ok_def max_msg_len_def)

(* A SURF_CREATE-shaped send to EP10 preserves deliveries⊆sends ... *)
lemma ipc_s4b_tagged_send_integrity:
  "c_integrity st \<Longrightarrow>
   c_integrity (fst (c_send s 10 [gui_surf_create_tag, sid, wh, fl] st))"
  by (simp add: ipc_send_integrity)

(* ... and the queued⊆sent invariant ... *)
lemma ipc_s4b_tagged_queued_subset:
  "set (sendq st j) \<subseteq> set (sent st) \<Longrightarrow>
   set (sendq (fst (c_send s 10 [gui_surf_create_tag, sid, wh, fl] st)) j) \<subseteq>
   set (sent (fst (c_send s 10 [gui_surf_create_tag, sid, wh, fl] st)))"
  by (simp add: ipc_send_queued_subset)

(* ... and EP separation (a tag-7 send to EP10 leaves every other EP
   bit-identical): the no_cross_deliver argument, instantiated. *)
lemma ipc_s4b_ep_separation:
  "j \<noteq> 10 \<Longrightarrow>
   sendq (fst (c_send s 10 [gui_surf_create_tag, sid, wh, fl] st)) j = sendq st j \<and>
   recvq (fst (c_send s 10 [gui_surf_create_tag, sid, wh, fl] st)) j = recvq st j"
  by (simp add: ep_separation_send)

(* ---- S4c input-IRQ pins (VirtIO keyboard/mouse for the gui qube) ----
   Shipped values, verbatim (kernel/kboot.c S4c: KBD_IRQ_BIT 0x4UL /
   MOUSE_IRQ_BIT 0x8UL; userspace/gui/v2_main.c polls the eventq only
   for IRQ bits WAIT actually returned, phase-split so armed input
   cannot starve FILL/COMPOSE). The model notifies raw nat signals, so
   deliveries\<subseteq>sends (c_integrity) + take-and-clear WAIT already
   quantify over ALL signals and the new bits inherit them by
   instantiation (instance lemmas below pin exactly that). max_eps is
   UNCHANGED (no-bump). Zero axioms. *)

definition kbd_irq_bit :: nat where
  "kbd_irq_bit = 4"

definition mouse_irq_bit :: nat where
  "mouse_irq_bit = 8"

(* Bits distinct (two independent IRQ sources). *)
lemma input_irq_bits_distinct:
  "kbd_irq_bit \<noteq> mouse_irq_bit"
  by (simp add: kbd_irq_bit_def mouse_irq_bit_def)

(* No-bump pin: the S4c IRQ set rides the S4a bound unchanged. *)
lemma max_eps_s4c_unchanged:
  "max_eps = 11"
  by (simp add: max_eps_def)

(* A kbd NOTIFY preserves deliveries\<subseteq>sends ... *)
lemma ipc_s4c_kbd_notify_integrity:
  "c_integrity st \<Longrightarrow> c_integrity (c_notify t kbd_irq_bit st)"
  by (simp add: ipc_notify_integrity)

(* ... and a mouse NOTIFY ... *)
lemma ipc_s4c_mouse_notify_integrity:
  "c_integrity st \<Longrightarrow> c_integrity (c_notify t mouse_irq_bit st)"
  by (simp add: ipc_notify_integrity)

(* ... and WAIT preserves it after a kbd IRQ fired ... *)
lemma ipc_s4c_input_wait_integrity:
  "c_integrity st \<Longrightarrow> c_integrity (fst (c_wait t (c_notify u kbd_irq_bit st)))"
  by (simp add: ipc_notify_integrity ipc_wait_integrity)

(* A kbd IRQ accumulates on the target thread (the badge WAIT takes). *)
lemma ipc_s4c_kbd_accumulates:
  "t < nthreads_of st \<Longrightarrow>
   ntfy (c_notify t kbd_irq_bit st) t = ntfy st t \<union> {kbd_irq_bit}"
  by (simp add: ipc_notify_accumulates)

(* A kbd IRQ wakes a WAIT-blocked gui qube (tid 10) ... *)
lemma ipc_s4c_kbd_wakes_gui:
  "\<lbrakk>10 < nthreads_of st; wk st 10 = 3\<rbrakk> \<Longrightarrow>
   v (cm (c_notify 10 kbd_irq_bit st)) = tcb_resume 10 (v (cm st)) \<and>
   wk (c_notify 10 kbd_irq_bit st) 10 = 0 \<and>
   kbd_irq_bit \<in> ntfy (c_notify 10 kbd_irq_bit st) 10"
  by (simp add: ipc_notify_wakes)

(* ... but never disturbs its rendezvous block. *)
lemma ipc_s4c_kbd_keeps_rendezvous:
  "\<lbrakk>10 < nthreads_of st; wk st 10 \<noteq> 3\<rbrakk> \<Longrightarrow>
   v (cm (c_notify 10 kbd_irq_bit st)) = v (cm st) \<and>
   wk (c_notify 10 kbd_irq_bit st) = wk st \<and>
   kbd_irq_bit \<in> ntfy (c_notify 10 kbd_irq_bit st) 10"
  by (simp add: ipc_notify_keeps_rendezvous)

(* WAIT takes a pending kbd bit and clears it (poll-only-when-notified:
   the ELF polls the eventq only for bits WAIT returned). *)
lemma ipc_s4c_kbd_take_clears:
  "let st1 = c_notify 1 4 init_cstate;
       (st2, bits) = c_wait 1 st1
   in (bits, ntfy st2 (1::nat), wk st2 (1::nat)) = ({4}, {}, 0)"
  by eval

(* Same shape for the mouse bit. *)
lemma ipc_s4c_mouse_take_clears:
  "let st1 = c_notify 1 8 init_cstate;
       (st2, bits) = c_wait 1 st1
   in (bits, ntfy st2 (1::nat), wk st2 (1::nat)) = ({8}, {}, 0)"
  by eval

(* ---- PCI-scan bounds (S4a GUI: userspace/gui/pci.h + v2_main.c bind) ----
   The ELF scans bus 0 only (PCI_BUS0_ONLY): dev < 32, fn < 8. pci_cfg_off
   is the ECAM offset (bus*1MB + dev*2KB + fn*256); the bochs slot binds
   iff its id pair is (0x1234 = 4660, 0x1111 = 4369), fetched verbatim
   from QEMU source, never from memory. BAR0 (cfg 0x10) must pass the
   size gate: nonzero base/size, size <= 64M, base aligned to size
   (power-of-two + nowrap are C-side conjuncts of pci_bar_ok, pinned by
   the host KATs in tests/test_gui.c; the HOL gate pins the shape the
   kernel relies on: GUI_LFB_MAX + alignment of GUI_LFB_PHYS).
   Zero axioms. *)

definition pci_ndev :: nat where
  "pci_ndev = 32"

definition pci_nfn :: nat where
  "pci_nfn = 8"

definition pci_slot_ok :: "nat \<Rightarrow> nat \<Rightarrow> bool" where
  "pci_slot_ok d f = (d < pci_ndev \<and> f < pci_nfn)"

definition pci_cfg_off :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat" where
  "pci_cfg_off bus d f = bus * 1048576 + d * 2048 + f * 256"

definition pci_bus0_window :: nat where
  "pci_bus0_window = 65536"

(* Bus-0 exactness: no bus-stride term (mirrors pci_cfg_off(0,d,f);
   KAT: pci_cfg_off(0,31,7) = 31*2048 + 7*256 in tests/test_gui.c). *)
lemma pci_cfg_exact:
  "pci_cfg_off 0 d f = d * 2048 + f * 256"
  by (simp add: pci_cfg_off_def)

(* The bus-0 scan covers every bindable slot. *)
lemma pci_scan_covers:
  "d < pci_ndev \<Longrightarrow> f < pci_nfn \<Longrightarrow> pci_slot_ok d f"
  by (simp add: pci_slot_ok_def)

(* Reach is exactly the scan rectangle. *)
lemma pci_scan_reach_exact:
  "pci_slot_ok d f = (d < 32 \<and> f < 8)"
  by (simp add: pci_slot_ok_def pci_ndev_def pci_nfn_def)

(* Every scanned slot's config lies inside the bus-0 ECAM window
   (max off = 31*2048 + 7*256 = 65280 < 65536). *)
lemma pci_bus0_covers:
  "pci_slot_ok d f \<Longrightarrow> pci_cfg_off 0 d f < pci_bus0_window"
  unfolding pci_slot_ok_def pci_cfg_off_def pci_ndev_def pci_nfn_def
            pci_bus0_window_def
  by arith

(* Bus-1 devices are invisible by construction: the scan hardwires bus 0
   (PCI_BUS0_ONLY), and every bus-1 offset lies above the whole bus-0
   window (min bus-1 off = 1MB). *)
lemma pci_bus1_invisible:
  "pci_bus0_window \<le> pci_cfg_off 1 d f"
  unfolding pci_cfg_off_def pci_bus0_window_def by arith

(* Bochs-display IDs (QEMU pci.h 0x1234 / bochs-display.c 0x1111). *)
definition pci_bochs_ven :: nat where
  "pci_bochs_ven = 4660"

definition pci_bochs_dev :: nat where
  "pci_bochs_dev = 4369"

(* A scanned slot binds iff its id pair is the bochs pair. *)
definition pci_binds :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool" where
  "pci_binds ven dev d f =
    (pci_slot_ok d f \<and> ven = pci_bochs_ven \<and> dev = pci_bochs_dev)"

lemma pci_bind_needs_scan:
  "pci_binds ven dev d f \<Longrightarrow> pci_slot_ok d f"
  by (simp add: pci_binds_def)

lemma pci_bind_is_bochs:
  "pci_binds ven dev d f \<Longrightarrow> ven = pci_bochs_ven \<and> dev = pci_bochs_dev"
  by (simp add: pci_binds_def)

lemma pci_bind_ex:
  "pci_binds pci_bochs_ven pci_bochs_dev 0 0"
  by (simp add: pci_binds_def pci_slot_ok_def pci_ndev_def pci_nfn_def
               pci_bochs_ven_def pci_bochs_dev_def)

(* ---- BAR-size gate (pci.h pci_bar_ok, 64M LFB cap) ---- *)

definition pci_lfb_max :: nat where
  "pci_lfb_max = 67108864"

definition pci_bar_ok :: "nat \<Rightarrow> nat \<Rightarrow> bool" where
  "pci_bar_ok base sz =
    (base \<noteq> 0 \<and> sz \<noteq> 0 \<and> sz \<le> pci_lfb_max \<and> base mod sz = 0)"

lemma pci_bar_gate:
  "pci_bar_ok base sz \<Longrightarrow>
   base \<noteq> 0 \<and> sz \<noteq> 0 \<and> sz \<le> pci_lfb_max \<and> base mod sz = 0"
  by (simp add: pci_bar_ok_def)

(* Kernel-assigned BAR (GUI_LFB_PHYS 0x40000000, 16M default LFB) passes;
   pinned by the host KAT pci_bar_ok(0x40000000, 0x1000000). *)
definition pci_demo_base :: nat where
  "pci_demo_base = 1073741824"

definition pci_demo_size :: nat where
  "pci_demo_size = 16777216"

lemma pci_demo_bar_ok:
  "pci_bar_ok pci_demo_base pci_demo_size"
  by (simp add: pci_bar_ok_def pci_demo_base_def pci_demo_size_def
               pci_lfb_max_def)

(* ---- Mutants: every new invariant can fail ---- *)

(* Scan-miss: dev 32 is off the 32-device scan, never bound. *)
definition pci_mutant_miss_d :: nat where
  "pci_mutant_miss_d = 32"

lemma pci_mutant_miss_bad:
  "\<not> pci_slot_ok pci_mutant_miss_d 0"
  by (simp add: pci_mutant_miss_d_def pci_slot_ok_def pci_ndev_def)

(* Oversize BAR: 64M+1 exceeds the gate. *)
definition pci_mutant_big :: nat where
  "pci_mutant_big = pci_lfb_max + 1"

lemma pci_mutant_big_bad:
  "\<not> pci_bar_ok pci_mutant_big pci_mutant_big"
  unfolding pci_mutant_big_def pci_bar_ok_def pci_lfb_max_def by arith

(* Bus-1 offset sits outside the bus-0 window (invisible by construction). *)
definition pci_mutant_bus1 :: nat where
  "pci_mutant_bus1 = pci_cfg_off 1 0 0"

lemma pci_mutant_bus1_bad:
  "pci_bus0_window \<le> pci_mutant_bus1"
  unfolding pci_mutant_bus1_def pci_cfg_off_def pci_bus0_window_def by arith

lemma pci_invariants_nontrivial:
  "(\<exists>d f. \<not> pci_slot_ok d f) \<and> (\<exists>b s. \<not> pci_bar_ok b s) \<and>
   (\<exists>off. pci_bus0_window \<le> off)"
  using pci_mutant_miss_bad pci_mutant_big_bad pci_mutant_bus1_bad by blast

(* ---- RNG-scan bounds (vault virtio-rng: rng_scan.h + kboot tid-8 leaf) ----
   The vault ELF scans the 8 virtio-mmio transports (VIRTIO_NTRANSPORTS 8):
   rng_scan n is the covered prefix (capped at 8, so index 8 is the OOB
   sentinel, never a transport). The transport U-leaf exists ONLY in tid
   8's tables (l1_t[8][5], boot-asserted "RNGMMIO: tid=8 only"): rng_leaf
   pins the owner, and the tid-6 mutant pin rejects the NET alias.
   Zero axioms. *)

definition rng_scan :: "nat \<Rightarrow> nat" where
  "rng_scan n = (if n \<le> 8 then n else 8)"

definition rng_leaf :: "nat \<Rightarrow> bool" where
  "rng_leaf t = (t = 8)"

lemma rng_mmio_covers: "rng_scan 8 = 8"
  by (simp add: rng_scan_def)
lemma rng_tid8_only: "rng_leaf t \<Longrightarrow> t = 8"
  by (simp add: rng_leaf_def)
lemma rng_mutant_leak_rejected: "rng_leaf 6 = False"
  by (simp add: rng_leaf_def)

(* ---- Input-transport scan bounds (gui virtio-kbd/mouse: v2_main.c
   KBD/MOUSE_MMIO_UVA + kboot tid-10 leaves + dev-18 discovery) ----
   The gui ELF probes the 8 virtio-mmio transports (VIRTIO_NTRANSPORTS
   8): input_scan n is the covered prefix (capped at 8, so index 8 is
   the OOB sentinel, never a transport). Both U-leaves exist ONLY in
   tid 10's tables (l1_t[10][9] kbd, l1_t[10][10] mouse, boot-asserted
   "GUIMMIO: tid=10 only"): input_leaf pins the owner, and the tid-9
   mutant pin rejects the BLK-neighbor alias. Discovery takes the
   first dev-18 as mouse and the second as kbd (cmdline order).
   Zero axioms. *)

definition input_scan :: "nat \<Rightarrow> nat" where
  "input_scan n = (if n \<le> 8 then n else 8)"

definition input_leaf :: "nat \<Rightarrow> bool" where
  "input_leaf t = (t = 10)"

lemma input_mmio_covers: "input_scan 8 = 8"
  by (simp add: input_scan_def)
lemma input_tid10_only: "input_leaf t \<Longrightarrow> t = 10"
  by (simp add: input_leaf_def)
lemma input_mutant_leak_rejected: "input_leaf 9 = False"
  by (simp add: input_leaf_def)

(* Falsifiability: the new invariants can fail (a foreign bit is not
   the kbd bit; a non-gui thread does not own the input leaf). *)
lemma input_invariants_nontrivial:
  "(\<exists>b. b \<noteq> kbd_irq_bit) \<and> (\<exists>t. \<not> input_leaf t)"
proof -
  have w1: "mouse_irq_bit \<noteq> kbd_irq_bit"
    by (simp add: kbd_irq_bit_def mouse_irq_bit_def)
  have w2: "\<not> input_leaf 9"
    by (simp add: input_leaf_def)
  from w1 w2 show ?thesis by blast
qed

end
