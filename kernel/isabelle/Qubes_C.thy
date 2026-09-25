theory Qubes_C
imports Qubes_B
begin

(* Moonlight Qubes S3: packet plane - firewall + net integrity over Qubes_B.
   This theory formalizes userspace/firewall/fw.h (first-match-wins,
   default-deny, IPv4/TCP-UDP/ports guards), userspace/net/v2_main.c (the
   T_FWD grant chain: announce (frame, len, hash) + kernel-stamped sender,
   hash recheck, silent drop) and kernel/qube.h arg carry (arg0/arg1 ride
   along, never interpreted). It ties the packet plane to the abstract
   model: fw_decide Allow plus a verified hash is the only path that
   delivers stored bytes, and every C-bounded frame/qube configuration is
   spec-bounded. All functions total and executable. Zero axioms.
   Model notes (binding ledger, Task 4 review):
   - IRQ source is DATA 1..8: the NIC is found by scanning 8 transports
     (kernel/kboot.c scan, net_find ranges j < 8); transport-0/IRQ-1
     hardcoding is false, so irq is irq_of_index ti with ti < 8 and the
     only claim is irq_of_index_valid. No lemma states irq = 1.
   - Net MMIO reach is 8 pages: mmio_page_ok p = (p < 8), and the U-leaf
     exists only for tid 6 (mmio_allowed tid = (tid = 6)), preserving the
     tid-6-only isolation.
   - qsnd is kernel-stamped (RECV returns sender tid in a1 and sender qube
     in a2; U-mode cannot forge it). stamp_ok ties the tid to its label;
     net_step additionally requires the firewall qube, so a spoofed or
     mis-stamped announcement is a silent drop, never acted on.
   - T_DELIVER carries no src: the broker ASK row pinned src == 0 before
     approval, so the firewall decides against the approved client label
     0 (FW_CLIENT). ASK verdicts resolve as deny (no prompter path).
   Anti-vacuity: every invariant ships with a mutant that violates it;
   Allow and Deny are both pinned by eval; no definition is trivially
   True. *)

(* ---- Packet model (mirrors fw.h bounds) ---- *)

definition FW_PKT_MAX :: nat where
  "FW_PKT_MAX = 1514"

definition FW_PROTO_TCP :: nat where
  "FW_PROTO_TCP = 6"

definition FW_PROTO_UDP :: nat where
  "FW_PROTO_UDP = 17"

(* Wire length bound: len > 1514 is deny (fw.h fw_decide length guard). *)
definition pkt_len_ok :: "nat list \<Rightarrow> bool" where
  "pkt_len_ok b = (length b \<le> FW_PKT_MAX)"

(* Executable stand-in for qube_fnv1a: byte sum over the frame. Any total
   hash works for the verify-then-deliver argument (delivery is gated on
   hash equality, never on collision resistance, which is not modeled).
   Sum is deliberately multiplication-free: eval codegen uses unary nats,
   so a polynomial hash diverges on real packets while a sum is instant. *)
definition pkt_hash :: "nat list \<Rightarrow> nat" where
  "pkt_hash b = fold (+) b 0"

(* Wellformedness mirrors the fw_decide guard chain: 14B eth + 20B IP-min
   + 4B ports, IPv4 ethertype, TCP-or-UDP proto. *)
definition pkt_wellformed :: "nat list \<Rightarrow> bool" where
  "pkt_wellformed b =
   (38 \<le> length b \<and> length b \<le> FW_PKT_MAX \<and>
    b ! 12 = 8 \<and> b ! 13 = 0 \<and>
    (b ! 23 = FW_PROTO_TCP \<or> b ! 23 = FW_PROTO_UDP))"

(* Minimal 38B packet constructor: ethertype at [12..13], proto at [23],
   big-endian dport at [36..37] (fw.h reads bytes[+2]<<8 | bytes[+3]). *)
definition mk_pkt :: "nat \<Rightarrow> nat \<Rightarrow> nat list" where
  "mk_pkt proto dport =
   (((((replicate 38 0)[12 := 8])[13 := 0])[23 := proto])[36 := dport div 256])[37 := dport mod 256]"

lemma mk_pkt_len:
  "length (mk_pkt p d) = 38"
  by (simp add: mk_pkt_def)

lemma mk_pkt_wellformed:
  "(proto = FW_PROTO_TCP \<or> proto = FW_PROTO_UDP) \<Longrightarrow> pkt_wellformed (mk_pkt proto dport)"
  by (simp add: mk_pkt_def pkt_wellformed_def FW_PKT_MAX_def
                FW_PROTO_TCP_def FW_PROTO_UDP_def)

(* ---- Firewall ruleset (mirrors fw.h fw_decide) ---- *)

(* None = wildcard (FW_ANY_QUBE / FW_ANY_PROTO / FW_ANY_PORT rows). *)
record fwrule =
  fsrc :: "nat option"
  fproto :: "nat option"
  fdport :: "nat option"
  fverdict :: decision

definition fw_match :: "fwrule \<Rightarrow> nat \<Rightarrow> nat list \<Rightarrow> bool" where
  "fw_match r src b =
   ((case fsrc r of None \<Rightarrow> True | Some x \<Rightarrow> x = src) \<and>
    (case fproto r of None \<Rightarrow> True | Some p \<Rightarrow> p = b ! 23) \<and>
    (case fdport r of None \<Rightarrow> True | Some p \<Rightarrow> p = b ! 36 * 256 + b ! 37))"

fun fw_loop :: "fwrule list \<Rightarrow> nat \<Rightarrow> nat list \<Rightarrow> decision" where
  "fw_loop [] _ _ = Deny" |
  "fw_loop (r # rest) src b =
   (if fw_match r src b then fverdict r else fw_loop rest src b)"

definition fw_decide :: "fwrule list \<Rightarrow> nat \<Rightarrow> nat list \<Rightarrow> decision" where
  "fw_decide rules src b = (if pkt_wellformed b then fw_loop rules src b else Deny)"

lemma fw_cons:
  "pkt_wellformed b \<Longrightarrow>
   fw_decide (r # rest) src b =
   (if fw_match r src b then fverdict r else fw_decide rest src b)"
  by (simp add: fw_decide_def)

lemma fw_loop_deny:
  "\<forall>r \<in> set rules. \<not> fw_match r src b \<Longrightarrow> fw_loop rules src b = Deny"
  by (induct rules) simp_all

(* Default-deny: no matching rule ==> Deny (fail closed). *)
lemma fw_default_deny_nomatch:
  assumes "pkt_wellformed b" "\<forall>r \<in> set rules. \<not> fw_match r src b"
  shows "fw_decide rules src b = Deny"
  using assms by (simp add: fw_decide_def fw_loop_deny)

(* Malformed ==> Deny, before any rule is consulted. *)
lemma fw_malformed_deny:
  "\<not> pkt_wellformed b \<Longrightarrow> fw_decide rules src b = Deny"
  by (simp add: fw_decide_def)

(* Empty table denies everything wellformed. *)
lemma fw_empty_deny:
  "pkt_wellformed b \<Longrightarrow> fw_decide [] src b = Deny"
  by (simp add: fw_decide_def)

(* Allow is only reachable through the wellformed path. *)
lemma fw_allow_needs_wellformed:
  "fw_decide rules src b = Allow \<Longrightarrow> pkt_wellformed b"
  unfolding fw_decide_def by (auto split: if_splits)

(* Boot ruleset v0 (firewall v2_main.c): {0, UDP, 53, ALLOW},
   {0, TCP, 443, ASK}, {ANY, ANY, ANY, DENY}. *)
definition demo_fw :: "fwrule list" where
  "demo_fw =
   [\<lparr>fsrc = Some 0, fproto = Some FW_PROTO_UDP, fdport = Some 53, fverdict = Allow\<rparr>,
    \<lparr>fsrc = Some 0, fproto = Some FW_PROTO_TCP, fdport = Some 443, fverdict = Ask\<rparr>,
    \<lparr>fsrc = None, fproto = None, fdport = None, fverdict = Deny\<rparr>]"

(* Order witness: deny-before-allow for the same key (first match wins). *)
definition demo_ord :: "fwrule list" where
  "demo_ord =
   [\<lparr>fsrc = Some 0, fproto = Some FW_PROTO_TCP, fdport = Some 80, fverdict = Deny\<rparr>,
    \<lparr>fsrc = Some 0, fproto = Some FW_PROTO_TCP, fdport = Some 80, fverdict = Allow\<rparr>]"

(* Allow and Deny both pinned by evaluation. *)
lemma demo_fw_allow:
  "fw_decide demo_fw 0 (mk_pkt FW_PROTO_UDP 53) = Allow"
  by eval

lemma demo_fw_deny_nomatch:
  "fw_decide demo_fw 0 (mk_pkt FW_PROTO_TCP 22) = Deny"
  by eval

lemma demo_fw_ask:
  "fw_decide demo_fw 0 (mk_pkt FW_PROTO_TCP 443) = Ask"
  by eval

lemma demo_fw_empty:
  "fw_decide [] 0 (mk_pkt FW_PROTO_UDP 53) = Deny"
  by eval

lemma demo_fw_order:
  "fw_decide demo_ord 0 (mk_pkt FW_PROTO_TCP 80) = Deny"
  by eval

lemma demo_fw_short:
  "fw_decide demo_fw 0 (replicate 30 0) = Deny"
  by eval

lemma demo_fw_ports_trunc:
  "fw_decide demo_fw 0 (take 36 (mk_pkt FW_PROTO_TCP 80)) = Deny"
  by eval

lemma demo_fw_nonipv4:
  "fw_decide demo_fw 0 ((mk_pkt FW_PROTO_UDP 53)[12 := 134, 13 := 221]) = Deny"
  by eval

lemma demo_fw_oversize:
  "fw_decide demo_fw 0 (replicate 1515 0) = Deny"
  by eval

(* ---- Grant chain + net accept (mirrors net v2_main.c) ---- *)

(* Qube identities (boot wiring): firewall is qube 4 running as tid 5,
   net is tid 6; the approved client label is qube 0. *)
definition FW_QUBE :: nat where "FW_QUBE = 4"
definition FW_TID :: nat where "FW_TID = 5"
definition NET_TID :: nat where "NET_TID = 6"
definition FW_CLIENT :: nat where "FW_CLIENT = 0"

(* Single-flight slots (both sides use slot 8; distinct roles). *)
definition FW_IN_SLOT :: nat where "FW_IN_SLOT = 8"
definition NET_IN_SLOT :: nat where "NET_IN_SLOT = 8"

(* Announcement: kernel-stamped (tid, qube) pair plus the granted
   (frame slot, len, hash) triple. U-mode cannot forge qsnd. *)
record announce =
  qtid :: nat
  qsnd :: nat
  qslot :: nat
  qlen :: nat
  qhash :: nat

(* Kernel stamp check: the tid's label is the claimed sender qube. *)
definition stamp_ok :: "(nat \<Rightarrow> nat) \<Rightarrow> announce \<Rightarrow> bool" where
  "stamp_ok L a = (L (qtid a) = qsnd a)"

(* Trust predicate: actionable only from the firewall qube. *)
definition net_trusted :: "announce \<Rightarrow> bool" where
  "net_trusted a = (qsnd a = FW_QUBE)"

(* Net accept: stamp, sender, slot, len bound, then hash recheck over the
   mapped bytes. Any failure is None (silent drop, no reply, no marker). *)
definition net_step :: "(nat \<Rightarrow> nat list) \<Rightarrow> (nat \<Rightarrow> nat) \<Rightarrow> announce \<Rightarrow> nat list option" where
  "net_step store L a =
   (if \<not> stamp_ok L a then None
    else if qsnd a \<noteq> FW_QUBE then None
    else if qslot a \<noteq> NET_IN_SLOT then None
    else if qlen a = 0 \<or> qlen a > FW_PKT_MAX then None
    else if qhash a \<noteq> pkt_hash (take (qlen a) (store (qslot a))) then None
    else Some (take (qlen a) (store (qslot a))))"

(* A successful accept pins every guard: bytes, hash, sender, slot, len. *)
lemma net_step_some:
  assumes "net_step store L a = Some bs"
  shows "bs = take (qlen a) (store (qslot a)) \<and>
         qhash a = pkt_hash (take (qlen a) (store (qslot a))) \<and>
         qsnd a = FW_QUBE \<and> stamp_ok L a \<and>
         qslot a = NET_IN_SLOT \<and> qlen a \<noteq> 0 \<and> qlen a \<le> FW_PKT_MAX"
  using assms unfolding net_step_def stamp_ok_def FW_QUBE_def
    NET_IN_SLOT_def FW_PKT_MAX_def
  by (auto split: if_splits)

(* Non-firewall announcements are never acted on. *)
lemma net_trust:
  "qsnd a \<noteq> FW_QUBE \<Longrightarrow> net_step store L a = None"
  by (simp add: net_step_def)

(* Mis-stamped announcements are never acted on. *)
lemma net_step_stamp:
  "\<not> stamp_ok L a \<Longrightarrow> net_step store L a = None"
  by (simp add: net_step_def)

(* Full packet-plane delivery: verified bytes forwarded only on Allow.
   ASK resolves as deny (no prompter path from the firewall). *)
definition fw_net_deliver :: "fwrule list \<Rightarrow> (nat \<Rightarrow> nat list) \<Rightarrow> (nat \<Rightarrow> nat) \<Rightarrow> nat \<Rightarrow> announce \<Rightarrow> nat list option" where
  "fw_net_deliver rules store L src a =
   (case net_step store L a of None \<Rightarrow> None
    | Some bs \<Rightarrow> (if fw_decide rules src bs = Allow then Some bs else None))"

lemma net_trust_deliver:
  "qsnd a \<noteq> FW_QUBE \<Longrightarrow> fw_net_deliver rules store L src a = None"
  by (simp add: fw_net_deliver_def net_trust)

lemma net_stamp_deliver:
  "\<not> stamp_ok L a \<Longrightarrow> fw_net_deliver rules store L src a = None"
  by (simp add: fw_net_deliver_def net_step_stamp)

lemma fw_ask_denied:
  assumes "net_step store L a = Some bs" "fw_decide rules src bs = Ask"
  shows "fw_net_deliver rules store L src a = None"
  using assms by (simp add: fw_net_deliver_def)

(* (a) Packet integrity: delivered bytes are exactly the stored bytes
   when the hash verifies on the Allow path. *)
lemma packet_integrity:
  assumes "fw_net_deliver rules store L src a = Some bs"
  shows "bs = take (qlen a) (store (qslot a))"
proof -
  from assms obtain x where
    ns: "net_step store L a = Some x" and bsx: "bs = x"
    unfolding fw_net_deliver_def by (auto split: option.split_asm if_split_asm)
  from net_step_some[OF ns] bsx show ?thesis by simp
qed

(* Allow delivery additionally pins the firewall verdict, the hash
   equality, the trusted sender and the single-flight slot. *)
lemma deliver_allow_pins:
  assumes "fw_net_deliver rules store L src a = Some bs"
  shows "fw_decide rules src bs = Allow \<and>
         qhash a = pkt_hash bs \<and> qsnd a = FW_QUBE \<and>
         qslot a = NET_IN_SLOT \<and> qlen a \<le> FW_PKT_MAX"
proof -
  from assms obtain x where
    ns: "net_step store L a = Some x" and
    dec: "fw_decide rules src x = Allow" and bsx: "bs = x"
    unfolding fw_net_deliver_def by (auto split: option.split_asm if_split_asm)
  from net_step_some[OF ns] dec bsx show ?thesis by simp
qed

(* ---- Demo store + announcements (executable pins) ---- *)

definition demo_L :: "nat \<Rightarrow> nat" where
  "demo_L = (\<lambda>t. if t = FW_TID then FW_QUBE else 0)"

definition demo_store :: "nat \<Rightarrow> nat list" where
  "demo_store = (\<lambda>s. if s = NET_IN_SLOT then mk_pkt FW_PROTO_UDP 53 else [])"

definition demo_ann_ok :: announce where
  "demo_ann_ok =
   \<lparr>qtid = FW_TID, qsnd = FW_QUBE, qslot = NET_IN_SLOT,
    qlen = 38, qhash = pkt_hash (mk_pkt FW_PROTO_UDP 53)\<rparr>"

definition demo_ann_spoof :: announce where
  "demo_ann_spoof = demo_ann_ok\<lparr>qsnd := 0\<rparr>"

definition demo_ann_badhash :: announce where
  "demo_ann_badhash = demo_ann_ok\<lparr>qhash := pkt_hash (mk_pkt FW_PROTO_UDP 53) + 1\<rparr>"

definition demo_ann_badstamp :: announce where
  "demo_ann_badstamp = demo_ann_ok\<lparr>qtid := 9\<rparr>"

lemma demo_stamp_ok:
  "stamp_ok demo_L demo_ann_ok"
  by eval

lemma demo_net_accept:
  "net_step demo_store demo_L demo_ann_ok = Some (mk_pkt FW_PROTO_UDP 53)"
  by eval

lemma demo_deliver_ok:
  "fw_net_deliver demo_fw demo_store demo_L FW_CLIENT demo_ann_ok =
   Some (mk_pkt FW_PROTO_UDP 53)"
  by eval

lemma demo_net_spoof:
  "net_step demo_store demo_L demo_ann_spoof = None"
  by eval

lemma demo_deliver_spoof:
  "fw_net_deliver demo_fw demo_store demo_L FW_CLIENT demo_ann_spoof = None"
  by eval

lemma demo_net_badhash:
  "net_step demo_store demo_L demo_ann_badhash = None"
  by eval

lemma demo_net_badstamp:
  "net_step demo_store demo_L demo_ann_badstamp = None"
  by eval

lemma demo_c_ask_full:
  "audit (c_q_call q_work q_vault rpc_sign 9
           (demo_init\<lparr>pending :=
              replicate 32 \<lparr>asrc = 0, adst = 0, arpc = 0, ahash = 0\<rparr>\<rparr>)) =
   [\<lparr>osrc = q_work, odst = q_vault, orpc = rpc_sign, oallow = False\<rparr>]"
  by eval

(* ---- Packet-plane audit ops + preservation (e) ---- *)

(* Audit-only step for a packet outcome (qubes/pending untouched). *)
definition q_pkt_audit :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool \<Rightarrow> qstate \<Rightarrow> qstate" where
  "q_pkt_audit s d r ok st =
   st\<lparr>audit := audit st @ [\<lparr>osrc = s, odst = d, orpc = r, oallow = ok\<rparr>]\<rparr>"

(* State-level delivery: Allow verdicts audit True, drops audit False. *)
definition q_net_deliver :: "fwrule list \<Rightarrow> (nat \<Rightarrow> nat list) \<Rightarrow> (nat \<Rightarrow> nat) \<Rightarrow> nat \<Rightarrow> announce \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> qstate \<Rightarrow> qstate" where
  "q_net_deliver rules store L src a d r st =
   (case fw_net_deliver rules store L src a of None \<Rightarrow> q_pkt_audit src d r False st
    | Some _ \<Rightarrow> q_pkt_audit src d r True st)"

lemma pkt_audit_unique:
  "q_unique st \<Longrightarrow> q_unique (q_pkt_audit s d r ok st)"
  by (simp add: q_pkt_audit_def q_unique_def)

lemma pkt_audit_bounded:
  "q_bounded st \<Longrightarrow> q_bounded (q_pkt_audit s d r ok st)"
  by (simp add: q_pkt_audit_def q_bounded_def)

lemma pkt_audit_pbounded:
  "p_bounded st \<Longrightarrow> p_bounded (q_pkt_audit s d r ok st)"
  by (simp add: q_pkt_audit_def p_bounded_def)

lemma deliver_unique:
  "q_unique st \<Longrightarrow> q_unique (q_net_deliver rules store L src a d r st)"
  by (simp add: q_net_deliver_def q_pkt_audit_def q_unique_def split: option.split)

lemma deliver_bounded:
  "q_bounded st \<Longrightarrow> q_bounded (q_net_deliver rules store L src a d r st)"
  by (simp add: q_net_deliver_def q_pkt_audit_def q_bounded_def split: option.split)

lemma deliver_pbounded:
  "p_bounded st \<Longrightarrow> p_bounded (q_net_deliver rules store L src a d r st)"
  by (simp add: q_net_deliver_def q_pkt_audit_def p_bounded_def split: option.split)

lemma deliver_audit_allow:
  "fw_net_deliver rules store L src a = Some bs \<Longrightarrow>
   audit (q_net_deliver rules store L src a d r st) =
   audit st @ [\<lparr>osrc = src, odst = d, orpc = r, oallow = True\<rparr>]"
  by (simp add: q_net_deliver_def q_pkt_audit_def)

lemma deliver_audit_drop:
  "fw_net_deliver rules store L src a = None \<Longrightarrow>
   audit (q_net_deliver rules store L src a d r st) =
   audit st @ [\<lparr>osrc = src, odst = d, orpc = r, oallow = False\<rparr>]"
  by (simp add: q_net_deliver_def q_pkt_audit_def)

(* ---- Arg refinement (d): decide on (src,dst,rpc), args verbatim ---- *)

(* Carried ask: the spec ask plus the C arg0/arg1 payload
   (kernel/qube.h v2_qask_t; carried, never interpreted). *)
record carg =
  csrc :: nat
  cdst :: nat
  crpc :: nat
  chash :: nat
  carg0 :: nat
  carg1 :: nat

definition mk_cask :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> carg" where
  "mk_cask s d r h a0 a1 =
   \<lparr>csrc = s, cdst = d, crpc = r, chash = h, carg0 = a0, carg1 = a1\<rparr>"

definition cask_proj :: "carg \<Rightarrow> ask" where
  "cask_proj c = \<lparr>asrc = csrc c, adst = cdst c, arpc = crpc c, ahash = chash c\<rparr>"

(* Projection drops exactly the carried args. *)
lemma cask_proj_eq:
  "cask_proj (mk_cask s d r h a0 a1) = \<lparr>asrc = s, adst = d, arpc = r, ahash = h\<rparr>"
  by (simp add: cask_proj_def mk_cask_def)

(* Args ride along verbatim. *)
lemma args_verbatim:
  "carg0 (mk_cask s d r h a0 a1) = a0 \<and> carg1 (mk_cask s d r h a0 a1) = a1"
  by (simp add: mk_cask_def)

(* Decide with args: verdict on (src,dst,rpc), args passed through. *)
definition c_decide_args :: "prule list \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> decision \<times> (nat \<times> nat)" where
  "c_decide_args pol s d r a0 a1 = (c_decide pol s d r, (a0, a1))"

(* Refinement: the C decide-with-args equals the spec lookup on
   (src,dst,rpc) with the arg pair carried verbatim. *)
lemma c_decide_args_eq:
  "c_decide_args pol s d r a0 a1 = (find_decision pol s d r, (a0, a1))"
  by (simp add: c_decide_args_def c_decide_eq)

(* The verdict never depends on the carried args. *)
lemma decide_ignores_args:
  "fst (c_decide_args pol s d r a0 a1) = fst (c_decide_args pol s d r b0 b1)"
  by (simp add: c_decide_args_def)

lemma demo_args_same_decide:
  "fst (c_decide_args demo_policy q_work q_net rpc_fetch 7 64) =
   fst (c_decide_args demo_policy q_work q_net rpc_fetch 9 128)"
  by eval

lemma demo_args_verbatim:
  "snd (c_decide_args demo_policy q_work q_net rpc_fetch 7 64) = (7, 64)"
  by eval

lemma demo_cask_proj:
  "cask_proj (mk_cask 0 2 3 9 7 64) = \<lparr>asrc = 0, adst = 2, arpc = 3, ahash = 9\<rparr>"
  by eval

(* ---- C bounds imply spec bounds (C: <=9 qubes, 1 frame) ---- *)

(* Single-frame bound: one announce carries at most one max frame. *)
definition c_frame_bound :: "nat \<Rightarrow> bool" where
  "c_frame_bound len = (len \<noteq> 0 \<and> len \<le> FW_PKT_MAX)"

lemma c_frame_implies_spec:
  "c_frame_bound len \<Longrightarrow> len \<le> FW_PKT_MAX"
  by (simp add: c_frame_bound_def)

lemma c_packet_bounds:
  "c_qbounded st \<Longrightarrow> c_frame_bound (qlen a) \<Longrightarrow> q_bounded st \<and> qlen a \<le> FW_PKT_MAX"
  using c_qubes_implies_spec c_frame_implies_spec by blast

(* ---- IRQ source is DATA 1..8 (scan-then-bind, never hardcoded) ---- *)

(* IRQ of transport index ti (kboot scan: net_virtio_irq = 1 + ti). *)
definition irq_of_index :: "nat \<Rightarrow> nat" where
  "irq_of_index ti = 1 + ti"

(* The only claim: a found IRQ lies in 1..8 (ti < 8 is the scan bound). *)
definition valid_irq :: "nat \<Rightarrow> bool" where
  "valid_irq irq = (1 \<le> irq \<and> irq \<le> 8)"

lemma valid_irq_iff_range:
  "valid_irq irq = (irq \<in> {1..8})"
  by (simp add: valid_irq_def atLeastAtMost_iff)

lemma irq_of_index_valid:
  "ti < 8 \<Longrightarrow> valid_irq (irq_of_index ti)"
  unfolding valid_irq_def irq_of_index_def by arith

(* Scan witness at a non-zero index: nothing assumes transport 0. *)
lemma irq_scan_ex:
  "valid_irq (irq_of_index 4)"
  by eval

(* ---- Net MMIO reach is 8 pages, tid 6 only ---- *)

definition mmio_page_ok :: "nat \<Rightarrow> bool" where
  "mmio_page_ok p = (p < 8)"

lemma mmio_reach_exact:
  "mmio_page_ok p = (p \<in> {0..<8})"
  by (simp add: mmio_page_ok_def)

(* The driver scan covers exactly the reachable pages. *)
lemma mmio_scan_covers:
  "j < 8 \<Longrightarrow> mmio_page_ok j"
  by (simp add: mmio_page_ok_def)

(* The transport U-leaf exists only in tid 6's table. *)
definition mmio_allowed :: "nat \<Rightarrow> bool" where
  "mmio_allowed tid = (tid = 6)"

lemma mmio_tid6_only:
  "mmio_allowed t \<Longrightarrow> t = 6"
  unfolding mmio_allowed_def by simp

lemma demo_mmio_tid6:
  "mmio_allowed 6"
  by eval

lemma demo_mmio_tid5:
  "\<not> mmio_allowed 5"
  by eval

lemma mmio_page_bad:
  "\<not> mmio_page_ok 8"
  by (simp add: mmio_page_ok_def)

(* ---- Mutants: every invariant can fail ---- *)

definition mutant_c_dup :: qstate where
  "mutant_c_dup = init_qstate\<lparr>qubes := [2, 2]\<rparr>"

lemma mutant_c_dup_bad: "\<not> q_unique mutant_c_dup"
  by (simp add: mutant_c_dup_def q_unique_def)

definition mutant_c_many :: qstate where
  "mutant_c_many =
   init_qstate\<lparr>qubes := [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]\<rparr>"

lemma mutant_c_many_bad: "\<not> q_bounded mutant_c_many"
  by (simp add: mutant_c_many_def q_bounded_def max_qubes_def)

definition mutant_c_pend :: qstate where
  "mutant_c_pend =
   init_qstate\<lparr>pending :=
     replicate 33 \<lparr>asrc = 1, adst = 2, arpc = 1, ahash = 0\<rparr>\<rparr>"

lemma mutant_c_pend_bad: "\<not> p_bounded mutant_c_pend"
  by (simp add: mutant_c_pend_def p_bounded_def max_pending_def)

definition mutant_c_forge_L :: "nat \<Rightarrow> nat" where
  "mutant_c_forge_L = (\<lambda>n. if n = 5 then 4 else 0)"

lemma mutant_c_forge_bad:
  "\<not> raw_ok mutant_c_forge_L False 5 6"
  by (simp add: mutant_c_forge_L_def raw_ok_def)

definition mutant_c_oversize :: "nat list" where
  "mutant_c_oversize = replicate 1515 0"

lemma mutant_c_oversize_bad: "\<not> pkt_len_ok mutant_c_oversize"
  by (simp add: mutant_c_oversize_def pkt_len_ok_def FW_PKT_MAX_def)

lemma mutant_c_oversize_malformed: "\<not> pkt_wellformed mutant_c_oversize"
  by (simp add: mutant_c_oversize_def pkt_wellformed_def)

definition mutant_c_spoof :: announce where
  "mutant_c_spoof = demo_ann_ok\<lparr>qsnd := 0\<rparr>"

lemma mutant_c_spoof_bad: "\<not> net_trusted mutant_c_spoof"
  by (simp add: mutant_c_spoof_def demo_ann_ok_def net_trusted_def FW_QUBE_def)

definition mutant_c_irq9 :: nat where
  "mutant_c_irq9 = irq_of_index 8"

lemma mutant_c_irq9_bad: "\<not> valid_irq mutant_c_irq9"
  by (simp add: mutant_c_irq9_def irq_of_index_def valid_irq_def)

lemma c_invariants_nontrivial:
  "(\<exists>s. \<not> q_unique s) \<and> (\<exists>s. \<not> q_bounded s) \<and> (\<exists>s. \<not> p_bounded s) \<and>
   (\<exists>L s d. \<not> raw_ok L False s d) \<and>
   (\<exists>b. \<not> pkt_len_ok b) \<and> (\<exists>b. \<not> pkt_wellformed b) \<and>
   (\<exists>a. \<not> net_trusted a) \<and> (\<exists>irq. \<not> valid_irq irq) \<and>
   (\<exists>p. \<not> mmio_page_ok p) \<and> (\<exists>t. \<not> mmio_allowed t)"
  using mutant_c_dup_bad mutant_c_many_bad mutant_c_pend_bad
        mutant_c_forge_bad mutant_c_oversize_bad mutant_c_oversize_malformed
        mutant_c_spoof_bad mutant_c_irq9_bad mmio_page_bad demo_mmio_tid5
  by blast

end
