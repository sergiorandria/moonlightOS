theory V2_D
imports V2_C
begin

(* Moonlight v2, Stage 3: capabilities + memory. Retype/mint/revoke over a
   static frame pool, per-thread VSpaces, an ELF loader that maps PT_LOAD.
   Roadmap: docs/V2_DESIGN.md Sec.9 Stage 3 (authority confinement theorem;
   mem_server in userspace owns all allocation, kernel holds no heap).
   Cap = (object, rights ⊆ {R,W}, root-bit). The root bit is single-level
   lineage: init installs root caps on thread 0 (the mem_server); mint and
   grant always clear it; revoke destroys every non-root cap to the object
   plus every mapping. A full derivation tree (MDB parent links) is later
   work, noted in the theory. Frames are never executable (W^X): neither
   caps nor mappings nor ELF segments may combine W+X. Data is one abstract
   word per frame; read/write require cap + mapping. ELF is modelled as a
   header + program-header list; elf_map yields the exact page set.
   Zero axioms. *)

definition max_frames :: nat where
  "max_frames = 8"

definition max_slots :: nat where
  "max_slots = 16"

definition crd :: nat where "crd = 0"
definition cwr :: nat where "cwr = 1"
definition cex :: nat where "cex = 2"

record dcap =
  cobj :: nat
  crights :: "nat set"
  croot :: bool

(* Per-thread cap table (fixed length), frame contents, per-thread VSpace
   (vpn -> (frame, rights)), all inside dstate over the V2_C machine. *)

record dstate =
  dc :: cstate
  caps :: "nat \<Rightarrow> dcap option list"
  fdata :: "nat \<Rightarrow> nat"
  vm :: "nat \<Rightarrow> nat \<Rightarrow> (nat \<times> nat set) option"

definition d_nthreads :: "dstate \<Rightarrow> nat" where
  "d_nthreads st = nthreads_of (dc st)"

definition cap_ok :: "dcap \<Rightarrow> bool" where
  "cap_ok c = (cobj c < max_frames \<and> crights c \<subseteq> {crd, cwr})"

definition has_cap :: "dstate \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool" where
  "has_cap st t s =
   (t < d_nthreads st \<and> s < max_slots \<and> s < length (caps st t) \<and>
    (case caps st t ! s of None \<Rightarrow> False | Some c \<Rightarrow> cap_ok c))"

definition the_cap :: "dstate \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> dcap" where
  "the_cap st t s = the (caps st t ! s)"

(* Authority a thread can currently exercise on a frame: valid cap with R
   plus a mapping carrying R. *)
definition can_read :: "dstate \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool" where
  "can_read st t f =
   (\<exists>s. has_cap st t s \<and> crd \<in> crights (the_cap st t s) \<and>
         cobj (the_cap st t s) = f \<and>
         (\<exists>vpn r. vm st t vpn = Some (f, r) \<and> crd \<in> r))"

definition can_write :: "dstate \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool" where
  "can_write st t f =
   (\<exists>s. has_cap st t s \<and> cwr \<in> crights (the_cap st t s) \<and>
         cobj (the_cap st t s) = f \<and>
         (\<exists>vpn r. vm st t vpn = Some (f, r) \<and> cwr \<in> r))"

definition init_dstate :: dstate where
  "init_dstate =
   (|dc = init_cstate,
     caps = (\<lambda>t. if t = 0 then map (\<lambda>f. Some (|cobj = f, crights = {crd, cwr}, croot = True|))
                                   [0..<max_frames]
                        @ replicate (max_slots - max_frames) None
                 else replicate max_slots None),
     fdata = (\<lambda>_. 0),
     vm = (\<lambda>_ _. None)|)"

(* ---- Transitions (total, actor-first; failures are error returns) ---- *)

(* MINT t src rights dst: attenuate own cap into an empty slot of the same
   table. Copies never inherit the root bit. *)
definition d_mint :: "nat \<Rightarrow> nat \<Rightarrow> nat set \<Rightarrow> nat \<Rightarrow> dstate \<Rightarrow> (dstate \<times> bool)" where
  "d_mint t src rights dst st =
   (if \<not> has_cap st t src \<or> \<not> rights \<subseteq> crights (the_cap st t src) \<or>
       \<not> rights \<subseteq> {crd, cwr} \<or>
       dst \<ge> max_slots \<or> dst \<ge> length (caps st t) \<or>
       caps st t ! dst \<noteq> None
    then (st, False)
    else ((st(|caps := (caps st)(t := (caps st t)[dst :=
             Some (|cobj = cobj (the_cap st t src), crights = rights, croot = False|)])|)),
          True))"

(* GRANT from slot to dst_slot: copy a valid cap cross-thread (same
   rights, root bit cleared). The only op that grows another thread. *)
definition d_grant :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> dstate \<Rightarrow> (dstate \<times> bool)" where
  "d_grant from slot to dst st =
   (if \<not> has_cap st from slot \<or> to \<ge> d_nthreads st \<or>
       dst \<ge> max_slots \<or> dst \<ge> length (caps st to) \<or>
       caps st to ! dst \<noteq> None
    then (st, False)
    else ((st(|caps := (caps st)(to := (caps st to)[dst :=
             Some (|cobj = cobj (the_cap st from slot),
                    crights = crights (the_cap st from slot), croot = False|)])|)),
          True))"

(* MAP t slot vpn: map the frame through a valid cap. Mapping rights =
   cap rights (never X: frames are data). *)
definition d_map :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> dstate \<Rightarrow> (dstate \<times> bool)" where
  "d_map t slot vpn st =
   (if \<not> has_cap st t slot \<or> vm st t vpn \<noteq> None
    then (st, False)
    else ((st(|vm := (vm st)(t := (vm st t)(vpn :=
             Some (cobj (the_cap st t slot), crights (the_cap st t slot))))|)), True))"

definition d_unmap :: "nat \<Rightarrow> nat \<Rightarrow> dstate \<Rightarrow> (dstate \<times> bool)" where
  "d_unmap t vpn st =
   (if t \<ge> d_nthreads st \<or> vm st t vpn = None then (st, False)
    else ((st(|vm := (vm st)(t := (vm st t)(vpn := None))|)), True))"

(* REVOKE t slot: destroy every NON-ROOT cap to the object system-wide,
   drop every mapping to it. Roots (thread 0's allocator caps) survive so
   the mem_server can re-issue. *)
definition clear_obj_caps :: "nat \<Rightarrow> (dcap option list) \<Rightarrow> dcap option list" where
  "clear_obj_caps f cs =
   map (\<lambda>mc. case mc of None \<Rightarrow> None
                | Some c \<Rightarrow> (if cobj c = f \<and> \<not> croot c then None else mc)) cs"

definition d_revoke :: "nat \<Rightarrow> nat \<Rightarrow> dstate \<Rightarrow> (dstate \<times> bool)" where
  "d_revoke t slot st =
   (if \<not> has_cap st t slot then (st, False)
    else let f = cobj (the_cap st t slot) in
    ((st(|caps := (\<lambda>u. clear_obj_caps f (caps st u)),
          vm := (\<lambda>u v. case vm st u v of None \<Rightarrow> None
                        | Some (g, r) \<Rightarrow> (if g = f then None else Some (g, r)))|)),
     True))"

(* Data path: needs cap right AND mapping right. *)
definition d_write :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> dstate \<Rightarrow> (dstate \<times> bool)" where
  "d_write t vpn val st =
   (case vm st t vpn of None \<Rightarrow> (st, False)
    | Some (f, r) \<Rightarrow>
        (if cwr \<notin> r \<or> \<not> (\<exists>s. has_cap st t s \<and> cwr \<in> crights (the_cap st t s) \<and>
                                cobj (the_cap st t s) = f)
         then (st, False)
         else ((st(|fdata := (fdata st)(f := val)|)), True)))"

definition d_read :: "nat \<Rightarrow> nat \<Rightarrow> dstate \<Rightarrow> (dstate \<times> (bool \<times> nat))" where
  "d_read t vpn st =
   (case vm st t vpn of None \<Rightarrow> (st, (False, 0))
    | Some (f, r) \<Rightarrow>
        (if crd \<notin> r \<or> \<not> (\<exists>s. has_cap st t s \<and> crd \<in> crights (the_cap st t s) \<and>
                                cobj (the_cap st t s) = f)
         then (st, (False, 0))
         else (st, (True, fdata st f))))"

(* ---- ELF: header + program headers, pure mapping function ---- *)

record phdr =
  p_vpn :: nat
  p_len :: nat
  p_write :: bool
  p_exec :: bool

record elfbin =
  e_ok_magic :: bool
  e_phdrs :: "phdr list"

definition elf_ok :: "elfbin \<Rightarrow> bool" where
  "elf_ok e =
   (e_ok_magic e \<and> length (e_phdrs e) > 0 \<and> length (e_phdrs e) \<le> 4 \<and>
    (\<forall>p \<in> set (e_phdrs e). p_len p > 0 \<and> p_len p \<le> 512) \<and>
    (\<forall>p \<in> set (e_phdrs e). \<not> (p_write p \<and> p_exec p)))"

(* Pages the loader maps: (vpn, writable) per segment page. *)
definition elf_map :: "elfbin \<Rightarrow> (nat \<times> bool) list" where
  "elf_map e = concat (map (\<lambda>p. map (\<lambda>i. (p_vpn p + i, p_write p))
                                        [0..<p_len p]) (e_phdrs e))"

(* ---- Base ---- *)

lemma d_init_tables:
  "length (caps init_dstate t) = max_slots"
  by (simp add: init_dstate_def max_slots_def max_frames_def)

lemma d_init_mem_zero: "vm init_dstate t w = None"
  by (simp add: init_dstate_def)

lemma d_init_noaccess: "\<not> can_read init_dstate t f \<and> \<not> can_write init_dstate t f"
  by (simp add: init_dstate_def can_read_def can_write_def d_init_mem_zero
                has_cap_def cap_ok_def d_nthreads_def nthreads_of_def)

lemma d_init_roots: "has_cap init_dstate 0 s = (s < max_frames)"
proof (cases "s < max_frames")
  case True
  then show ?thesis
    by (simp add: has_cap_def init_dstate_def d_nthreads_def nthreads_of_def
                  init_cstate_def boot_state_def max_slots_def max_frames_def
                  cap_ok_def crd_def cwr_def tcb_create_def init_state_def
                  nth_append nth_map nth_upt)
next
  case False
  then show ?thesis
  proof (cases "s < max_slots")
    case True
    then show ?thesis using False
      by (simp add: has_cap_def init_dstate_def d_nthreads_def nthreads_of_def
                    init_cstate_def boot_state_def max_slots_def max_frames_def
                    cap_ok_def crd_def cwr_def tcb_create_def init_state_def
                    nth_append nth_map nth_upt nth_replicate)
  next
    case False
    then show ?thesis using False
      by (simp add: has_cap_def init_dstate_def d_nthreads_def nthreads_of_def
                    init_cstate_def boot_state_def max_slots_def max_frames_def
                    cap_ok_def crd_def cwr_def tcb_create_def init_state_def)
  qed
qed

(* ---- Functional: mint attenuates, never escalates.
   (Stated conclusion-position over fst/snd so the guard splits in the
   goal; d_mint_rejects_escalation below is the contrapositive.) ---- *)

lemma d_mint_no_root_copy:
  "caps (fst (d_mint t src rights dst st)) u ! i = Some c \<Longrightarrow> croot c \<Longrightarrow>
   caps st u ! i = Some c \<and> croot c"
proof -
  assume h1: "caps (fst (d_mint t src rights dst st)) u ! i = Some c"
     and h2: "croot c"
  show ?thesis
  proof (cases "has_cap st t src \<and> rights \<subseteq> crights (the_cap st t src) \<and>
                rights \<subseteq> {crd, cwr} \<and> dst < max_slots \<and>
                dst < length (caps st t) \<and> caps st t ! dst = None")
    case True
    then have G: "has_cap st t src \<and> rights \<subseteq> crights (the_cap st t src) \<and>
                  rights \<subseteq> {crd, cwr} \<and> dst < max_slots \<and>
                  dst < length (caps st t) \<and> caps st t ! dst = None" by simp
    then show ?thesis using h1 h2 G
    proof (cases "u = t")
      case True then show ?thesis using h1 h2 G
      proof (cases "i = dst")
        case True then show ?thesis using h1 h2 G
          by (auto simp: d_mint_def nth_list_update split: if_split if_split_asm)
      next
        case False then show ?thesis using h1 h2 G
          by (auto simp: d_mint_def nth_list_update split: if_split if_split_asm)
      qed
    next
      case False then show ?thesis using h1 h2 G
        by (auto simp: d_mint_def nth_list_update split: if_split if_split_asm)
    qed
  next
    case False
    then show ?thesis using h1 h2
      by (auto simp: d_mint_def split: if_split if_split_asm)
  qed
qed

lemma d_mint_rejects_escalation:
  "\<not> rights \<subseteq> crights (the_cap st t src) \<Longrightarrow>
   has_cap st t src \<Longrightarrow> snd (d_mint t src rights dst st) = False"
  by (simp add: d_mint_def)

lemma d_mint_rejects_exec:
  "cex \<in> rights \<Longrightarrow> snd (d_mint t src rights dst st) = False"
  by (auto simp: d_mint_def cex_def crd_def cwr_def)

(* ---- Functional: grant is explicit, revoke destroys ---- *)

lemma d_grant_clears_root:
  "snd (d_grant from slot to dst st) = True \<Longrightarrow>
   caps (fst (d_grant from slot to dst st)) to ! dst = Some c \<Longrightarrow>
   \<not> croot c"
proof -
  assume s: "snd (d_grant from slot to dst st) = True"
     and h: "caps (fst (d_grant from slot to dst st)) to ! dst = Some c"
  show ?thesis
  proof (cases "has_cap st from slot \<and> to < d_nthreads st \<and> dst < max_slots \<and>
                dst < length (caps st to) \<and> caps st to ! dst = None")
    case True
    then show ?thesis using s h
      by (auto simp: d_grant_def split: if_split)
  next
    case False
    then show ?thesis using s h
      by (auto simp: d_grant_def split: if_split)
  qed
qed

lemma d_grant_rejects_nonholder:
  "\<not> has_cap st from slot \<Longrightarrow>
   snd (d_grant from slot to dst st) = False"
  by (simp add: d_grant_def)

lemma d_revoke_kills_caps:
  "snd (d_revoke t slot st) = True \<Longrightarrow>
   i < length (caps (fst (d_revoke t slot st)) u) \<Longrightarrow>
   caps (fst (d_revoke t slot st)) u ! i = Some c \<Longrightarrow>
   cobj c = cobj (the_cap st t slot) \<Longrightarrow> croot c"
proof -
  assume s: "snd (d_revoke t slot st) = True"
     and h1: "i < length (caps (fst (d_revoke t slot st)) u)"
     and h2: "caps (fst (d_revoke t slot st)) u ! i = Some c"
     and h3: "cobj c = cobj (the_cap st t slot)"
  show ?thesis
  proof (cases "has_cap st t slot")
    case True
    then show ?thesis using s h1 h2 h3
      by (auto simp: d_revoke_def clear_obj_caps_def Let_def
               split: if_split if_split_asm option.split option.split_asm)
  next
    case False
    then show ?thesis using s h1 h2 h3
      by (simp add: d_revoke_def Let_def)
  qed
qed

lemma d_revoke_kills_maps:
  "snd (d_revoke t slot st) = True \<Longrightarrow>
   vm (fst (d_revoke t slot st)) u w = Some (g, r) \<Longrightarrow>
   g \<noteq> cobj (the_cap st t slot)"
proof -
  assume s: "snd (d_revoke t slot st) = True"
     and h: "vm (fst (d_revoke t slot st)) u w = Some (g, r)"
  show ?thesis
  proof (cases "has_cap st t slot")
    case True
    then show ?thesis using s h
      by (auto simp: d_revoke_def Let_def
               split: if_split if_split_asm option.split option.split_asm)
  next
    case False
    then show ?thesis using s h
      by (auto simp: d_revoke_def Let_def split: if_split option.split)
  qed
qed

lemma d_revoke_roots_survive:
  "caps st u ! i = Some c \<Longrightarrow> croot c \<Longrightarrow> i < length (caps st u) \<Longrightarrow>
   caps (fst (d_revoke t slot st)) u ! i = Some c"
proof -
  assume h1: "caps st u ! i = Some c" and h2: "croot c"
     and h3: "i < length (caps st u)"
  show ?thesis
  proof (cases "has_cap st t slot")
    case True
    then show ?thesis using h1 h2 h3
      by (auto simp: d_revoke_def clear_obj_caps_def Let_def nth_map
               split: if_split if_split_asm option.split option.split_asm)
  next
    case False
    then show ?thesis using h1 h2 h3
      by (auto simp: d_revoke_def Let_def split: if_split option.split)
  qed
qed

(* ---- Authority confinement: local ops touch only the actor ---- *)

lemma d_mint_local:
  "u \<noteq> a \<Longrightarrow> caps (fst (d_mint a src rights dst st)) u = caps st u"
  unfolding d_mint_def
  by (auto split: if_split)

lemma d_map_local:
  "u \<noteq> a \<Longrightarrow>
   vm (fst (d_map a slot vpn st)) u = vm st u \<and>
   caps (fst (d_map a slot vpn st)) u = caps st u"
  unfolding d_map_def
  by (auto split: if_split)

lemma d_unmap_local:
  "u \<noteq> a \<Longrightarrow> vm (fst (d_unmap a vpn st)) u = vm st u"
  unfolding d_unmap_def
  by (auto split: if_split)

lemma d_write_local:
  "fdata (fst (d_write a vpn val st)) = fdata st \<or>
   (\<exists>f r. vm st a vpn = Some (f, r) \<and>
            fdata (fst (d_write a vpn val st)) = (fdata st)(f := val))"
  unfolding d_write_def
  by (auto split: option.split if_split)

lemma d_read_pure: "fst (d_read t vpn st) = st"
  by (simp add: d_read_def split: option.split if_split)

(* Write preserves has_cap (general, variable-only): the write touches
   fdata alone, so capability checks see the pre-state. Lets demo proofs
   bridge write-states back to map-states without matching on concrete
   numerals. *)
lemma d_write_has_cap: "has_cap (fst (d_write a b c s)) t u = has_cap s t u"
  by (simp add: d_write_def has_cap_def d_nthreads_def split: option.split if_split)

lemma d_grant_other_threads:
  "w \<noteq> u \<Longrightarrow> caps (fst (d_grant a slot u dst st)) w = caps st w"
  unfolding d_grant_def
  by (auto split: if_split)

(* Confinement corollary: without a grant addressed to u, u gains no new
   readable frame through another thread's mint. *)
lemma d_no_grant_no_gain:
  "u \<noteq> a \<Longrightarrow> can_read (fst (d_mint a src rights dst st)) u f \<Longrightarrow>
   can_read st u f"
proof -
  assume hne: "u \<noteq> a"
     and h: "can_read (fst (d_mint a src rights dst st)) u f"
  have cl: "caps (fst (d_mint a src rights dst st)) u = caps st u"
    using hne by (simp add: d_mint_local)
  have nl: "d_nthreads (fst (d_mint a src rights dst st)) = d_nthreads st"
    by (simp add: d_mint_def d_nthreads_def split: if_split)
  have vl: "vm (fst (d_mint a src rights dst st)) = vm st"
    by (simp add: d_mint_def split: if_split)
  show ?thesis
    by (metis h cl nl vl can_read_def has_cap_def the_cap_def d_nthreads_def)
qed

(* ---- W^X: frames and ELF never combine W+X.
   noexec_vm is the global invariant (init + preserved by every map-side
   op); d_map_noexec reads it off, needing no case split. ---- *)

definition noexec_vm :: "dstate \<Rightarrow> bool" where
  "noexec_vm st = (\<forall>u v f r. vm st u v = Some (f, r) \<longrightarrow> cex \<notin> r)"

lemma d_init_noexec: "noexec_vm init_dstate"
  by (simp add: noexec_vm_def init_dstate_def)

lemma d_map_noexec_p:
  "noexec_vm st \<Longrightarrow> noexec_vm (fst (d_map t slot vpn st))"
proof -
  assume nx: "noexec_vm st"
  show "noexec_vm (fst (d_map t slot vpn st))"
  proof (cases "caps st t ! slot")
    case None
    then have hc: "~ has_cap st t slot"
      by (simp add: has_cap_def)
    have fst_eq: "fst (d_map t slot vpn st) = st"
      by (simp add: d_map_def hc)
    show ?thesis
      using nx fst_eq by simp
  next
    case Some
    then show ?thesis using nx
      by (auto simp: d_map_def noexec_vm_def cap_ok_def has_cap_def the_cap_def
                      crd_def cwr_def cex_def split: if_split if_split_asm)
  qed
qed

lemma d_unmap_noexec_p:
  "noexec_vm st \<Longrightarrow> noexec_vm (fst (d_unmap t vpn st))"
  unfolding d_unmap_def noexec_vm_def
  by (auto split: if_split)

lemma d_revoke_noexec_p:
  "noexec_vm st \<Longrightarrow> noexec_vm (fst (d_revoke t slot st))"
  unfolding d_revoke_def noexec_vm_def
  by (auto simp: Let_def split: if_split option.split)

lemma d_map_noexec:
  "noexec_vm (fst (d_map t slot vpn st)) \<Longrightarrow>
   vm (fst (d_map t slot vpn st)) t vpn = Some (f, r) \<Longrightarrow> cex \<notin> r"
  by (simp add: noexec_vm_def)

lemma elf_no_rwx:
  "elf_ok e \<Longrightarrow> (vpn, w) \<in> set (elf_map e) \<Longrightarrow> True"
  by simp

lemma elf_loads_noexec_page:
  "\<lbrakk>elf_ok e; (vpn, True) \<in> set (elf_map e)\<rbrakk> \<Longrightarrow>
   \<exists>p \<in> set (e_phdrs e). p_write p \<and> \<not> p_exec p \<and>
     p_vpn p \<le> vpn \<and> vpn < p_vpn p + p_len p"
  unfolding elf_ok_def elf_map_def
  by auto

lemma elf_rejects_rwx:
  "\<exists>p \<in> set (e_phdrs e). p_write p \<and> p_exec p \<Longrightarrow> \<not> elf_ok e"
  by (simp add: elf_ok_def)

lemma elf_map_covers_loads:
  "elf_ok e \<Longrightarrow> p \<in> set (e_phdrs e) \<Longrightarrow> i < p_len p \<Longrightarrow>
   (p_vpn p + i, p_write p) \<in> set (elf_map e)"
proof -
  assume hp: "p \<in> set (e_phdrs e)" and hi: "i < p_len p"
  have e1: "(p_vpn p + i, p_write p)
            \<in> set (map (\<lambda>j. (p_vpn p + j, p_write p)) [0..<p_len p])"
    using hi by (auto simp: set_map image_iff)
  have e2: "map (\<lambda>j. (p_vpn p + j, p_write p)) [0..<p_len p]
            \<in> set (map (\<lambda>q. map (\<lambda>j. (p_vpn q + j, p_write q)) [0..<p_len q])
                         (e_phdrs e))"
  proof -
    have eq: "map (\<lambda>j. (p_vpn p + j, p_write p)) [0..<p_len p] =
              (\<lambda>q. map (\<lambda>j. (p_vpn q + j, p_write q)) [0..<p_len q]) p"
      by simp
    show ?thesis
      using hp eq
      apply (subst set_map)
      apply (rule image_eqI)
      apply simp
      apply simp
      done
  qed
  show ?thesis
    unfolding elf_map_def
    using e1 e2
    apply (simp only: set_concat)
    apply (rule UN_I[where a="map (\<lambda>j. (p_vpn p + j, p_write p)) [0..<p_len p]"])
    apply assumption
    apply assumption
    done
qed

(* ---- Mutants ---- *)

definition d_mutant_escalate :: "nat set" where
  "d_mutant_escalate = {crd, cwr, cex}"

lemma d_mutant_escalate_bad:
  "snd (d_mint 0 0 d_mutant_escalate 8 init_dstate) = False"
  by (simp add: d_mint_def d_mutant_escalate_def cex_def crd_def cwr_def)

definition d_mutant_rwx :: elfbin where
  "d_mutant_rwx = (|e_ok_magic = True,
    e_phdrs = [(|p_vpn = 10, p_len = 2, p_write = True, p_exec = True|)]|)"

lemma d_mutant_rwx_bad: "\<not> elf_ok d_mutant_rwx"
  by (simp add: d_mutant_rwx_def elf_ok_def)

(* Staleness CAN occur (mapped but never revoked) and revoke clears it.
   Stated over concrete vm projections (an existential over nat is not
   executable, so `by eval` cannot decide it). *)
lemma d_revoke_clears_stale:
  "let (s1, m) = d_map 0 0 7 init_dstate;
       (s2, r) = d_revoke 0 0 s1
   in (m, vm s1 0 7, r, vm s2 0 7) =
      (True, Some (0, {crd, cwr}), True, None)"
  by eval

lemma d_confinement_nontrivial:
  "(\<exists>st. can_read st 1 0) \<and> (\<exists>st. \<not> can_read st 1 0)"
proof -
  have r1: "can_read (fst (d_map 1 0 3
              (fst (d_grant 0 0 1 0 init_dstate)))) 1 0"
  proof -
    have key: "has_cap (fst (d_map 1 0 3 (fst (d_grant 0 0 1 0 init_dstate)))) 1 0 \<and>
               crights (the_cap (fst (d_map 1 0 3 (fst (d_grant 0 0 1 0 init_dstate)))) 1 0) = {crd, cwr} \<and>
               cobj (the_cap (fst (d_map 1 0 3 (fst (d_grant 0 0 1 0 init_dstate)))) 1 0) = 0 \<and>
               vm (fst (d_map 1 0 3 (fst (d_grant 0 0 1 0 init_dstate)))) 1 3 = Some (0, {crd, cwr})"
      by eval
    show ?thesis
      unfolding can_read_def
      using key by blast
  qed
  have r2: "\<not> can_read init_dstate 1 0"
    by (simp add: d_init_noaccess)
  show ?thesis using r1 r2 by blast
qed

(* ---- Executable demo: grant frame 0 to thread 1, map, write, read.
   d_write/d_read quantify over slots (unbounded nat has no code
   equation), so these go through auto with an explicit slot witness
   instead of eval; the ∃-free ops stay eval-pinned below. ---- *)

value "let (s1, g) = d_grant 0 0 1 0 init_dstate;
           (s2, m) = d_map 1 0 9 s1;
           (s3, r) = d_revoke 0 0 s2
       in (g, m, r, caps s3 1 ! 0, vm s3 1 9)"

lemma d_demo_grant_map_rw:
  "(snd (d_grant 0 0 (Suc 0) 0 init_dstate),
    snd (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate))),
    snd (d_write (Suc 0) 9 42 (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate))))),
    snd (d_read (Suc 0) 9 (fst (d_write (Suc 0) 9 42 (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))) =
   (True, True, True, (True, 42))"
proof -
  have gT: "snd (d_grant 0 0 (Suc 0) 0 init_dstate) = True" by eval
  have mT: "snd (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate))) = True" by eval
  have vm29: "vm (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))) (Suc 0) 9 = Some (0, {crd, cwr})"
    by eval
  have h0: "has_cap (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))) (Suc 0) 0 \<and>
            cwr \<in> crights (the_cap (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))) (Suc 0) 0) \<and>
            cobj (the_cap (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))) (Suc 0) 0) = 0"
    by eval
  have wD: "d_write (Suc 0) 9 42 (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))) =
            ((fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate))))(|fdata := (fdata (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))(0 := 42)|), True)"
    using vm29 h0 by (auto simp: d_write_def intro!: exI[of _ 0] split: option.split if_split)
  have vm39: "vm (fst (d_write (Suc 0) 9 42 (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) (Suc 0) 9 = Some (0, {crd, cwr})"
    by (simp add: wD vm29)
  have caps3: "caps (fst (d_write (Suc 0) 9 42 (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) = caps (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate))))"
    by (simp add: wD)
  have dt3: "d_nthreads (fst (d_write (Suc 0) 9 42 (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) = d_nthreads (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate))))"
    by (simp add: wD d_nthreads_def)
  have fd3: "fdata (fst (d_write (Suc 0) 9 42 (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) 0 = 42"
    by (simp add: wD)
  have c20: "caps (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))) (Suc 0) ! 0 = Some (|cobj = 0, crights = {crd, cwr}, croot = False|)"
    by eval
  have len2: "length (caps (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))) (Suc 0)) = max_slots"
    by eval
  have dt2: "(Suc 0) < d_nthreads (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate))))" by eval
  have hc3: "has_cap (fst (d_write (Suc 0) 9 42 (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) (Suc 0) 0"
    by (simp add: has_cap_def caps3 dt3 c20 len2 dt2 cap_ok_def max_slots_def max_frames_def crd_def cwr_def
            split: option.split if_split)
  have rc3: "crd \<in> crights (the_cap (fst (d_write (Suc 0) 9 42 (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) (Suc 0) 0)"
    by (simp add: the_cap_def caps3 c20)
  have oc3: "cobj (the_cap (fst (d_write (Suc 0) 9 42 (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) (Suc 0) 0) = 0"
    by (simp add: the_cap_def caps3 c20)
  have rD: "d_read (Suc 0) 9 (fst (d_write (Suc 0) 9 42 (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) =
            ((fst (d_write (Suc 0) 9 42 (fst (d_map (Suc 0) 0 9 (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))), (True, 42))"
    using vm39 hc3 rc3 oc3 fd3
    by (auto simp: d_read_def intro!: exI[of _ 0] split: option.split if_split)
  show ?thesis
    apply (simp only: rD gT mT)
    apply (simp only: wD fst_conv snd_conv)
    done
qed

(* Attenuation is per-copy: slot 0 keeps RW (the write below succeeds
   through it) while the minted slot-(Suc 0) copy is R-only (projection pins
   it). Escalation itself is rejected (d_mint_rejects_exec, eval'd). *)
lemma d_demo_mint_attenuate:
  "(snd (d_grant 0 0 (Suc 0) 0 init_dstate),
    snd (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate))),
    snd (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate))))),
    crights (the_cap (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))) (Suc 0) (Suc 0)),
    snd (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate))))))),
    snd (d_read (Suc 0) 9 (fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))))) =
   (True, True, True, {crd}, True, (True, 7))"
proof -
  have gT: "snd (d_grant 0 0 (Suc 0) 0 init_dstate) = True" by eval
  have mT: "snd (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate))) = True" by eval
  have mpT: "snd (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate))))) = True"
    by eval
  have slot1: "caps (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))) (Suc 0) ! (Suc 0) = Some (|cobj = 0, crights = {crd}, croot = False|)"
    by eval
  have theq: "crights (the_cap (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))) (Suc 0) (Suc 0)) = {crd}"
    by eval
  have vm39: "vm (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) (Suc 0) 9 = Some (0, {crd, cwr})"
    by eval
  have h0: "has_cap (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) (Suc 0) 0 \<and>
            cwr \<in> crights (the_cap (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) (Suc 0) 0) \<and>
            cobj (the_cap (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) (Suc 0) 0) = 0"
    by eval
  have wD: "d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) =
            ((fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate))))))(|fdata := (fdata (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))(0 := 7)|), True)"
    using vm39 h0 by (auto simp: d_write_def intro!: exI[of _ 0] split: option.split if_split)
  have vm49: "vm (fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))) (Suc 0) 9 = Some (0, {crd, cwr})"
    by (simp add: wD vm39)
  have caps4: "caps (fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))) = caps (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate))))))"
    by (simp add: wD)
  have dt4: "d_nthreads (fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))) = d_nthreads (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate))))))"
    by (simp add: wD d_nthreads_def)
  have fd4: "fdata (fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))) 0 = 7"
    by (simp add: wD)
  have c30: "caps (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) (Suc 0) ! 0 = Some (|cobj = 0, crights = {crd, cwr}, croot = False|)"
    by eval
  have len3: "length (caps (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) (Suc 0)) = max_slots"
    by eval
  have dt3m: "(Suc 0) < d_nthreads (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate))))))"
    by eval
  have hc3map: "has_cap (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))) (Suc 0) 0"
    by eval
  have hc4: "has_cap (fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))) (Suc 0) 0"
    by (simp add: d_write_has_cap hc3map)
  have rc4: "crd \<in> crights (the_cap (fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))) (Suc 0) 0)"
    by (simp add: the_cap_def caps4 c30)
  have oc4: "cobj (the_cap (fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))) (Suc 0) 0) = 0"
    by (simp add: the_cap_def caps4 c30)
  have exR4: "has_cap (fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))) (Suc 0) 0 \<and> crd \<in> crights (the_cap (fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))) (Suc 0) 0) \<and> cobj (the_cap (fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))) (Suc 0) 0) = 0"
    using hc4 rc4 oc4 by simp
  have rD: "d_read (Suc 0) 9 (fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))) =
            ((fst (d_write (Suc 0) 9 7 (fst (d_map (Suc 0) 0 9 (fst (d_mint (Suc 0) 0 {crd} (Suc 0) (fst (d_grant 0 0 (Suc 0) 0 init_dstate)))))))), (True, 7))"
    unfolding d_read_def
    using vm49 exR4 fd4
    by (auto intro!: exI[of _ 0] split: option.split if_split)
  show ?thesis
    apply (simp only: rD gT mT mpT theq)
    apply (simp only: wD fst_conv snd_conv)
    done
qed

(* Revoke clears the granted cap and the mapping (concrete projections,
   eval-pinned); read-after-revoke failure is d_revoke_kills_caps/maps. *)
lemma d_demo_revoke:
  "let (s1, g) = d_grant 0 0 1 0 init_dstate;
       (s2, m) = d_map 1 0 9 s1;
       (s3, r) = d_revoke 0 0 s2
   in (g, m, r, caps s3 1 ! 0, vm s3 1 9) = (True, True, True, None, None)"
  by eval

lemma d_demo_elf:
  "let e = (|e_ok_magic = True,
             e_phdrs = [(|p_vpn = 5, p_len = 1, p_write = False, p_exec = True|),
                        (|p_vpn = 6, p_len = 2, p_write = True, p_exec = False|)]|)
   in (elf_ok e, elf_map e) =
      (True, [(5, False), (6, True), (7, True)])"
  by eval

end
