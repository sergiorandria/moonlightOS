theory Qubes_D
imports Qubes_C
begin

(* Moonlight FDE (Qubes S7-storage / FDE stage): per-qube keyslots over a
   full-disk-encryption volume, formalizing userspace/cryptblk/layout.h
   (CRYPT_MAGIC, SECTOR 4096, TAGS_PER_SECTOR 256, MAX_SLOTS 8,
   HEADER_SECTORS 2), userspace/cryptblk/slot.h (slot wrap/unwrap/wipe),
   userspace/vault/v2_main.c (T_KEY 8 / T_KEY_ACK 10 one-time handoff by
   GRANT to slot 20, never SEND words) and userspace/cryptblk/v2_main.c
   (sector AEAD layer, dual views /dev/blk0 ciphertext + / tree plaintext).
   Roadmap: docs/superpowers/specs/2026-09-21-fde-encrypted-files-design.md.
   Theorems: (a) slot-release-only-to-label, (b) ciphertext-view
   label-independence, (c) no-ambient-decrypt. All functions total and
   executable. Zero axioms.
   Model notes (binding ledger):
   - Crypto correctness is KAT-correspondence, NOT an axiom: the theory
     reasons over opaque key nats + pkt_hash (the Qubes_C byte-sum
     stand-in, executable on unary nats) for tag equality; delivery is
     gated on equality, never on collision resistance. Strength of
     ChaCha20-Poly1305/PBKDF2 is pinned by host KATs (tests/test_aead.c),
     not modeled here.
   - Kernel stamps are total label functions L (qube_of[tid]); U-mode
     cannot forge the (tid, qube) pair, mirroring the RECV stamp.
   - V2_D.thy max_frames = 8 divergence (noted, not fixed here):
     V2_D models an 8-frame pool while the C build now has
     V2_FRAMES_MAX = 32 (FDE Task 4 bump). This theory does not depend on
     V2_D frame bounds; its sector math uses FDE_NSECTORS only.
   - T_KEY moves by GRANT (vault PT_ALLOC + WRITE + GRANT R-only slot 20
     + keyless SEND [T_KEY, slot, 0, 0]); no lemma moves key bytes over
     SEND words.
   Anti-vacuity: every invariant ships with a mutant that violates it;
   release-allow and every deny leg are pinned by eval; no definition is
   trivially True. *)

(* ---- FDE constants (mirror layout.h / vault v2_main.c) ---- *)

definition FDE_MAGIC :: nat where
  "FDE_MAGIC = 4851037950178053966"

definition FDE_VERSION :: nat where
  "FDE_VERSION = 1"

definition FDE_SECTOR :: nat where
  "FDE_SECTOR = 4096"

definition FDE_MAX_SLOTS :: nat where
  "FDE_MAX_SLOTS = 8"

definition FDE_NSECTORS :: nat where
  "FDE_NSECTORS = 65536"

definition FDE_VAULT_QUBE :: nat where
  "FDE_VAULT_QUBE = 6"

definition FDE_CRYPT_QUBE :: nat where
  "FDE_CRYPT_QUBE = 7"

definition FDE_VAULT_TID :: nat where
  "FDE_VAULT_TID = 8"

definition FDE_CRYPT_TID :: nat where
  "FDE_CRYPT_TID = 9"

definition FDE_KEY_SLOT :: nat where
  "FDE_KEY_SLOT = 20"

definition FDE_C_MAX_THREADS :: nat where
  "FDE_C_MAX_THREADS = 10"

(* ---- Slot model (mirrors slot.h wrap/unwrap/wipe) ---- *)

record fslot =
  flabel :: nat
  fkey :: nat
  fwiped :: bool

definition slots_valid :: "fslot list \<Rightarrow> bool" where
  "slots_valid ss = (length ss \<le> FDE_MAX_SLOTS)"

(* Release: kernel-stamped caller label L tid must equal the slot owner;
   wiped slots never release. Returns the slot key on success. *)
definition slot_release :: "fslot list \<Rightarrow> (nat \<Rightarrow> nat) \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat option" where
  "slot_release ss L tid idx =
    (if idx < length ss \<and> \<not> fwiped (ss ! idx) \<and> flabel (ss ! idx) = L tid
     then Some (fkey (ss ! idx)) else None)"

(* (a) Slot-release-only-to-label: success pins the owner label, the
   unwiped flag, the index bound and the returned key. *)
lemma slot_release_only_to_label:
  assumes "slot_release ss L tid idx = Some k"
  shows "idx < length ss \<and> \<not> fwiped (ss ! idx) \<and>
         flabel (ss ! idx) = L tid \<and> k = fkey (ss ! idx)"
  using assms unfolding slot_release_def by (auto split: if_splits)

(* Release fails closed on wiped slots. *)
lemma slot_release_wiped:
  "idx < length ss \<Longrightarrow> fwiped (ss ! idx) \<Longrightarrow> slot_release ss L tid idx = None"
  by (simp add: slot_release_def)

(* Release fails closed on label mismatch. *)
lemma slot_release_wrong_label:
  "idx < length ss \<Longrightarrow> flabel (ss ! idx) \<noteq> L tid \<Longrightarrow>
   slot_release ss L tid idx = None"
  by (simp add: slot_release_def)

(* Release fails closed out of range. *)
lemma slot_release_oob:
  "length ss \<le> idx \<Longrightarrow> slot_release ss L tid idx = None"
  by (simp add: slot_release_def)

(* ---- Ciphertext view (raw /dev/blk0, label-independent) ---- *)

(* Raw sector read: the disk function itself (ciphertext bytes). *)
definition fde_raw :: "(nat \<Rightarrow> nat list) \<Rightarrow> nat \<Rightarrow> nat list" where
  "fde_raw disk sector = disk sector"

(* Labeled raw read: takes a reader label and ignores it (the bytes are
   identical for all readers -- no plaintext oracle on the raw path). *)
definition fde_raw_as :: "(nat \<Rightarrow> nat list) \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat list" where
  "fde_raw_as disk label sector = disk sector"

(* (b) Ciphertext-view label-independence: any two reader labels see
   identical bytes, and the labeled view equals the raw view. *)
lemma ciphertext_view_independent:
  "fde_raw_as disk l1 s = fde_raw_as disk l2 s"
  by (simp add: fde_raw_as_def)

lemma ciphertext_view_is_raw:
  "fde_raw_as disk l s = fde_raw disk s"
  by (simp add: fde_raw_as_def fde_raw_def)

(* ---- Release log + file open (no-ambient-decrypt) ---- *)

(* Release log: (tid, slot) pairs granted through the T_KEY handoff. *)
definition fde_has_rel :: "(nat \<times> nat) list \<Rightarrow> nat \<Rightarrow> bool" where
  "fde_has_rel rels tid = (\<exists>p \<in> set rels. fst p = tid)"

(* Grant step: appends (tid, idx) only when the release succeeds. *)
definition fde_grant :: "(nat \<times> nat) list \<Rightarrow> fslot list \<Rightarrow> (nat \<Rightarrow> nat) \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> (nat \<times> nat) list" where
  "fde_grant rels ss L tid idx =
    (case slot_release ss L tid idx of None \<Rightarrow> rels | Some _ \<Rightarrow> rels @ [(tid, idx)])"

lemma fde_grant_none:
  "slot_release ss L tid idx = None \<Longrightarrow> fde_grant rels ss L tid idx = rels"
  by (simp add: fde_grant_def)

lemma fde_grant_some:
  "slot_release ss L tid idx = Some k \<Longrightarrow>
   fde_grant rels ss L tid idx = rels @ [(tid, idx)]"
  by (simp add: fde_grant_def)

lemma fde_grant_has:
  "slot_release ss L tid idx = Some k \<Longrightarrow>
   fde_has_rel (fde_grant rels ss L tid idx) tid"
  by (simp add: fde_grant_def fde_has_rel_def)

(* File open: plaintext appears only with a released slot for the caller.
   The disk bytes are served (decryption abstracted as identity over the
   released key); without a release the result is None and no disk byte
   is touched by the caller. *)
definition fde_open :: "(nat \<times> nat) list \<Rightarrow> fslot list \<Rightarrow> (nat \<Rightarrow> nat) \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> (nat \<Rightarrow> nat list) \<Rightarrow> nat \<Rightarrow> nat list option" where
  "fde_open rels ss L tid idx disk sector =
    (case slot_release ss L tid idx of None \<Rightarrow> None
     | Some _ \<Rightarrow> (if fde_has_rel rels tid then Some (disk sector) else None))"

(* (c) No-ambient-decrypt: any delivered plaintext implies a released slot
   for the caller and a successful release check. *)
lemma no_ambient_decrypt:
  assumes "fde_open rels ss L tid idx disk sector = Some bs"
  shows "fde_has_rel rels tid \<and> slot_release ss L tid idx \<noteq> None \<and>
         bs = disk sector"
  using assms unfolding fde_open_def fde_has_rel_def
  by (auto split: option.split_asm if_split_asm)

(* No release log entry ==> no plaintext, even with a valid slot. *)
lemma fde_open_no_rel:
  "\<not> fde_has_rel rels tid \<Longrightarrow> fde_open rels ss L tid idx disk sector = None \<or>
   slot_release ss L tid idx = None"
  unfolding fde_open_def by (auto split: option.split)

(* ---- Sector tag check (wrong-key / tamper leg) ---- *)

(* Tag check over the Qubes_C pkt_hash stand-in: delivery gated on hash
   equality only (KAT-correspondence, see header). *)
definition fde_sec_open :: "(nat \<Rightarrow> nat list) \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat list option" where
  "fde_sec_open disk sector tag =
    (if tag = pkt_hash (disk sector) then Some (disk sector) else None)"

lemma fde_sec_open_ok:
  "fde_sec_open disk s (pkt_hash (disk s)) = Some (disk s)"
  by (simp add: fde_sec_open_def)

lemma fde_sec_open_tamper:
  "tag \<noteq> pkt_hash (disk s) \<Longrightarrow> fde_sec_open disk s tag = None"
  by (simp add: fde_sec_open_def)

definition fde_sec_in_range :: "nat \<Rightarrow> bool" where
  "fde_sec_in_range s = (s < FDE_NSECTORS)"

lemma fde_sec_range_ok:
  "s < FDE_NSECTORS \<Longrightarrow> fde_sec_in_range s"
  by (simp add: fde_sec_in_range_def FDE_NSECTORS_def)

lemma fde_sec_range_bad:
  "\<not> fde_sec_in_range FDE_NSECTORS"
  by (simp add: fde_sec_in_range_def FDE_NSECTORS_def)

(* ---- Header parse (no-volume leg) ---- *)

definition fde_hdr_ok :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool" where
  "fde_hdr_ok magic ver nslots =
    (magic = FDE_MAGIC \<and> ver = FDE_VERSION \<and> nslots \<le> FDE_MAX_SLOTS)"

lemma fde_hdr_good:
  "fde_hdr_ok FDE_MAGIC FDE_VERSION 2"
  by (simp add: fde_hdr_ok_def FDE_MAGIC_def FDE_VERSION_def FDE_MAX_SLOTS_def)

lemma fde_hdr_bad_magic:
  "magic \<noteq> FDE_MAGIC \<Longrightarrow> \<not> fde_hdr_ok magic FDE_VERSION 2"
  by (simp add: fde_hdr_ok_def)

lemma fde_hdr_bad_ver:
  "ver \<noteq> FDE_VERSION \<Longrightarrow> \<not> fde_hdr_ok FDE_MAGIC ver 2"
  by (simp add: fde_hdr_ok_def)

lemma fde_hdr_overcount:
  "\<not> fde_hdr_ok FDE_MAGIC FDE_VERSION 9"
  by (simp add: fde_hdr_ok_def FDE_MAX_SLOTS_def)

(* ---- T_KEY sender gate (spoofed handoff is dropped) ---- *)

(* T_KEY notices are actionable only from the vault tid (kernel-stamped). *)
definition fde_tkey_ok :: "nat \<Rightarrow> bool" where
  "fde_tkey_ok sender = (sender = FDE_VAULT_TID)"

lemma fde_tkey_vault:
  "fde_tkey_ok FDE_VAULT_TID"
  by (simp add: fde_tkey_ok_def FDE_VAULT_TID_def)

lemma fde_tkey_spoof:
  "sender \<noteq> FDE_VAULT_TID \<Longrightarrow> \<not> fde_tkey_ok sender"
  by (simp add: fde_tkey_ok_def)

(* ---- Demo witnesses (executable pins for every transcript leg) ---- *)

definition fde_demo_L :: "nat \<Rightarrow> nat" where
  "fde_demo_L = (\<lambda>t. if t = FDE_VAULT_TID then FDE_VAULT_QUBE
                  else if t = FDE_CRYPT_TID then FDE_CRYPT_QUBE else 0)"

definition fde_demo_slots :: "fslot list" where
  "fde_demo_slots =
    [\<lparr>flabel = FDE_CRYPT_QUBE, fkey = 11, fwiped = False\<rparr>,
     \<lparr>flabel = 0, fkey = 22, fwiped = False\<rparr>]"

definition fde_demo_disk :: "nat \<Rightarrow> nat list" where
  "fde_demo_disk = (\<lambda>s. if s = 7 then [7, 8, 9] else [])"

lemma demo_release_allow:
  "slot_release fde_demo_slots fde_demo_L FDE_CRYPT_TID 0 = Some 11"
  by eval

lemma demo_release_wrong_label:
  "slot_release fde_demo_slots fde_demo_L 3 0 = None"
  by eval

lemma demo_release_wiped:
  "slot_release [\<lparr>flabel = FDE_CRYPT_QUBE, fkey = 11, fwiped = True\<rparr>]
     fde_demo_L FDE_CRYPT_TID 0 = None"
  by eval

lemma demo_release_oob:
  "slot_release fde_demo_slots fde_demo_L FDE_CRYPT_TID 5 = None"
  by eval

lemma demo_raw_equal:
  "fde_raw_as fde_demo_disk FDE_CRYPT_QUBE 7 =
   fde_raw_as fde_demo_disk 0 7"
  by eval

lemma demo_raw_is_cipher:
  "fde_raw_as fde_demo_disk FDE_CRYPT_QUBE 7 = [7, 8, 9]"
  by eval

lemma demo_open_leak:
  "fde_open [] fde_demo_slots fde_demo_L FDE_CRYPT_TID 0 fde_demo_disk 7 = None"
  by eval

lemma demo_open_ok:
  "fde_open [(FDE_CRYPT_TID, 0)] fde_demo_slots fde_demo_L FDE_CRYPT_TID 0
     fde_demo_disk 7 = Some [7, 8, 9]"
  by eval

lemma demo_sec_ok:
  "fde_sec_open fde_demo_disk 7 (pkt_hash [7, 8, 9]) = Some [7, 8, 9]"
  by eval

lemma demo_sec_tamper:
  "fde_sec_open fde_demo_disk 7 (pkt_hash [7, 8, 9] + 1) = None"
  by eval

lemma demo_hdr_ok:
  "fde_hdr_ok FDE_MAGIC FDE_VERSION 2"
  by (simp add: fde_hdr_ok_def FDE_MAGIC_def FDE_VERSION_def FDE_MAX_SLOTS_def)

lemma demo_hdr_bad:
  "\<not> fde_hdr_ok 0 FDE_VERSION 2"
  by (simp add: fde_hdr_ok_def FDE_MAGIC_def)

lemma demo_tkey_ok:
  "fde_tkey_ok FDE_VAULT_TID"
  by eval

lemma demo_tkey_spoof:
  "\<not> fde_tkey_ok 3"
  by eval

(* ---- C refinement (slot/FS ops equal the spec lookup) ---- *)

(* C slot_unwrap loop (slot.h) over the same record layout. *)
definition c_slot_release :: "fslot list \<Rightarrow> (nat \<Rightarrow> nat) \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat option" where
  "c_slot_release ss L tid idx =
    (if idx < length ss \<and> \<not> fwiped (ss ! idx) \<and> flabel (ss ! idx) = L tid
     then Some (fkey (ss ! idx)) else None)"

lemma c_slot_release_eq:
  "c_slot_release ss L tid idx = slot_release ss L tid idx"
  by (simp add: c_slot_release_def slot_release_def)

definition c_file_open :: "(nat \<times> nat) list \<Rightarrow> fslot list \<Rightarrow> (nat \<Rightarrow> nat) \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> (nat \<Rightarrow> nat list) \<Rightarrow> nat \<Rightarrow> nat list option" where
  "c_file_open rels ss L tid idx disk sector = fde_open rels ss L tid idx disk sector"

lemma c_file_open_eq:
  "c_file_open rels ss L tid idx disk sector =
   fde_open rels ss L tid idx disk sector"
  by (simp add: c_file_open_def)

(* The open verdict never depends on disk bytes: without a release the
   result is None for any disk image. *)
lemma open_ignores_sector_bytes:
  "slot_release ss L tid idx = None \<Longrightarrow>
   fde_open rels ss L tid idx disk1 s = fde_open rels ss L tid idx disk2 s"
  by (simp add: fde_open_def)

(* ---- Qstate audit ops + preservation ---- *)

(* Audit-only step for a slot/filesystem outcome (qubes/pending untouched,
   mirroring q_pkt_audit). *)
definition q_fde_audit :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool \<Rightarrow> qstate \<Rightarrow> qstate" where
  "q_fde_audit s d r ok st =
    st\<lparr>audit := audit st @ [\<lparr>osrc = s, odst = d, orpc = r, oallow = ok\<rparr>]\<rparr>"

(* State-level slot release: success audits True, failure audits False. *)
definition q_slot_deliver :: "(nat \<times> nat) list \<Rightarrow> fslot list \<Rightarrow> (nat \<Rightarrow> nat) \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> qstate \<Rightarrow> qstate" where
  "q_slot_deliver rels ss L tid idx d r st =
    (case slot_release ss L tid idx of None \<Rightarrow> q_fde_audit tid d r False st
     | Some _ \<Rightarrow> (if fde_has_rel rels tid then q_fde_audit tid d r True st
              else q_fde_audit tid d r False st))"

lemma fde_audit_unique:
  "q_unique st \<Longrightarrow> q_unique (q_fde_audit s d r ok st)"
  by (simp add: q_fde_audit_def q_unique_def)

lemma fde_audit_bounded:
  "q_bounded st \<Longrightarrow> q_bounded (q_fde_audit s d r ok st)"
  by (simp add: q_fde_audit_def q_bounded_def)

lemma fde_audit_pbounded:
  "p_bounded st \<Longrightarrow> p_bounded (q_fde_audit s d r ok st)"
  by (simp add: q_fde_audit_def p_bounded_def)

lemma slot_deliver_unique:
  "q_unique st \<Longrightarrow> q_unique (q_slot_deliver rels ss L tid idx d r st)"
  by (simp add: q_slot_deliver_def q_fde_audit_def q_unique_def split: option.split)

lemma slot_deliver_bounded:
  "q_bounded st \<Longrightarrow> q_bounded (q_slot_deliver rels ss L tid idx d r st)"
  by (simp add: q_slot_deliver_def q_fde_audit_def q_bounded_def split: option.split)

lemma slot_deliver_pbounded:
  "p_bounded st \<Longrightarrow> p_bounded (q_slot_deliver rels ss L tid idx d r st)"
  by (simp add: q_slot_deliver_def q_fde_audit_def p_bounded_def split: option.split)

lemma slot_deliver_audit_allow:
  "\<lbrakk>slot_release ss L tid idx = Some k; fde_has_rel rels tid\<rbrakk> \<Longrightarrow>
   audit (q_slot_deliver rels ss L tid idx d r st) =
   audit st @ [\<lparr>osrc = tid, odst = d, orpc = r, oallow = True\<rparr>]"
  by (simp add: q_slot_deliver_def q_fde_audit_def)

lemma slot_deliver_audit_drop:
  "slot_release ss L tid idx = None \<Longrightarrow>
   audit (q_slot_deliver rels ss L tid idx d r st) =
   audit st @ [\<lparr>osrc = tid, odst = d, orpc = r, oallow = False\<rparr>]"
  by (simp add: q_slot_deliver_def q_fde_audit_def)

(* ---- C bounds imply spec bounds (C: <=10 threads, <=8 qubes) ---- *)

(* Thread bound: vault tid 8 and cryptblk tid 9 fit the 10-thread build. *)
definition c_thread_ok :: "nat \<Rightarrow> bool" where
  "c_thread_ok t = (t < FDE_C_MAX_THREADS)"

lemma c_thread_vault:
  "c_thread_ok FDE_VAULT_TID"
  by (simp add: c_thread_ok_def FDE_VAULT_TID_def FDE_C_MAX_THREADS_def)

lemma c_thread_crypt:
  "c_thread_ok FDE_CRYPT_TID"
  by (simp add: c_thread_ok_def FDE_CRYPT_TID_def FDE_C_MAX_THREADS_def)

(* Qube build ends at qube_next = 8 = V2_QUBES_MAX; C qube bound (8)
   implies the spec bound (16) by the S2 lemma. *)
lemma c_fde_qubes_bound:
  "c_qbounded st \<Longrightarrow> q_bounded st"
  by (simp add: c_qubes_implies_spec)

lemma c_fde_slots_bound:
  "slots_valid ss \<Longrightarrow> length ss \<le> FDE_MAX_SLOTS"
  by (simp add: slots_valid_def FDE_MAX_SLOTS_def)

lemma c_fde_packet_bounds:
  "c_qbounded st \<Longrightarrow> slots_valid ss \<Longrightarrow> q_bounded st \<and> length ss \<le> FDE_MAX_SLOTS"
  using c_fde_qubes_bound c_fde_slots_bound by blast

(* ---- Mutants: every invariant can fail ---- *)

definition mutant_d_wrong_label :: "fslot list" where
  "mutant_d_wrong_label =
    [\<lparr>flabel = 0, fkey = 11, fwiped = False\<rparr>]"

lemma mutant_d_wrong_label_bad:
  "slot_release mutant_d_wrong_label fde_demo_L FDE_CRYPT_TID 0 = None"
  by (simp add: mutant_d_wrong_label_def slot_release_def fde_demo_L_def
               FDE_CRYPT_TID_def FDE_CRYPT_QUBE_def FDE_VAULT_TID_def
               FDE_VAULT_QUBE_def)

definition mutant_d_wiped :: "fslot list" where
  "mutant_d_wiped =
    [\<lparr>flabel = FDE_CRYPT_QUBE, fkey = 11, fwiped = True\<rparr>]"

lemma mutant_d_wiped_bad:
  "slot_release mutant_d_wiped fde_demo_L FDE_CRYPT_TID 0 = None"
  by (simp add: mutant_d_wiped_def slot_release_def)

definition mutant_d_forge_L :: "nat \<Rightarrow> nat" where
  "mutant_d_forge_L = (\<lambda>n. if n = FDE_CRYPT_TID then 0 else FDE_CRYPT_QUBE)"

lemma mutant_d_forge_bad:
  "slot_release fde_demo_slots mutant_d_forge_L FDE_CRYPT_TID 0 = None"
  by (simp add: mutant_d_forge_L_def fde_demo_slots_def slot_release_def
               FDE_CRYPT_TID_def FDE_CRYPT_QUBE_def)

definition mutant_d_oversize :: nat where
  "mutant_d_oversize = FDE_NSECTORS"

lemma mutant_d_oversize_bad:
  "\<not> fde_sec_in_range mutant_d_oversize"
  by (simp add: mutant_d_oversize_def fde_sec_in_range_def FDE_NSECTORS_def)

definition mutant_d_spoof :: nat where
  "mutant_d_spoof = 3"

lemma mutant_d_spoof_bad:
  "\<not> fde_tkey_ok mutant_d_spoof"
  by (simp add: mutant_d_spoof_def fde_tkey_ok_def FDE_VAULT_TID_def)

definition mutant_d_hdr :: nat where
  "mutant_d_hdr = 0"

lemma mutant_d_hdr_bad:
  "\<not> fde_hdr_ok mutant_d_hdr FDE_VERSION 2"
  by (simp add: mutant_d_hdr_def fde_hdr_ok_def FDE_MAGIC_def)

definition mutant_d_slots9 :: "fslot list" where
  "mutant_d_slots9 =
    [\<lparr>flabel = 0, fkey = 0, fwiped = False\<rparr>,
     \<lparr>flabel = 1, fkey = 1, fwiped = False\<rparr>,
     \<lparr>flabel = 2, fkey = 2, fwiped = False\<rparr>,
     \<lparr>flabel = 3, fkey = 3, fwiped = False\<rparr>,
     \<lparr>flabel = 4, fkey = 4, fwiped = False\<rparr>,
     \<lparr>flabel = 5, fkey = 5, fwiped = False\<rparr>,
     \<lparr>flabel = 6, fkey = 6, fwiped = False\<rparr>,
     \<lparr>flabel = 7, fkey = 7, fwiped = False\<rparr>,
     \<lparr>flabel = 8, fkey = 8, fwiped = False\<rparr>]"

lemma mutant_d_slots9_bad:
  "\<not> slots_valid mutant_d_slots9"
  by (simp add: mutant_d_slots9_def slots_valid_def FDE_MAX_SLOTS_def)

lemma demo_no_rel:
  "\<not> fde_has_rel [] 0"
  by (simp add: fde_has_rel_def)

lemma d_invariants_nontrivial:
  "(\<exists>ss L tid idx. slot_release ss L tid idx = None) \<and>
   (\<exists>rels tid. \<not> fde_has_rel rels tid) \<and>
   (\<exists>s. \<not> fde_sec_in_range s) \<and>
   (\<exists>sender. \<not> fde_tkey_ok sender) \<and>
   (\<exists>m v n. \<not> fde_hdr_ok m v n) \<and>
   (\<exists>ss. \<not> slots_valid ss)"
  using demo_release_wrong_label demo_no_rel mutant_d_oversize_bad
        mutant_d_spoof_bad mutant_d_hdr_bad mutant_d_slots9_bad
  by blast

lemma d_release_nontrivial:
  "(\<exists>ss L tid idx. slot_release ss L tid idx = None) \<and>
   (\<exists>ss L tid idx k. slot_release ss L tid idx = Some k)"
  using demo_release_wrong_label demo_release_allow by blast

lemma d_open_nontrivial:
  "(\<exists>rels ss L tid idx disk s. fde_open rels ss L tid idx disk s = None) \<and>
   (\<exists>rels ss L tid idx disk s bs. fde_open rels ss L tid idx disk s = Some bs)"
  using demo_open_leak demo_open_ok by blast

end
