theory FS_Verification
imports Moonlight_A
begin

(* Userspace VFS, verified to kernel-equivalent strength. Mirrors
   userspace/vfs_server/server.c guard-for-guard: per-client fd tables keyed
   by the kernel-authenticated sender, rights-checked IO, wrap-safe bounds,
   owner-only create/unlink, no unlink-while-open, unique names.
   Natural numbers make overflow impossible by construction; the C side keeps
   every quantity below 2^20 with pre-clamping. File backing caps reuse the
   system cap model (Moonlight_A.cap_valid), so VFS validity composes with
   the kernel invariants instead of inventing a second notion of authority.
   fd entries are a RECORD (not a tuple): tuple patterns in case/forall get
   normalized away by automation and break rule matching; selectors stay
   atomic. No axioms, no sledgehammer-cheats: everything below is proved. *)

(* Rights are booleans (FR = read-bit present, FW = write-bit present), so the
   prover's built-in bool case analysis closes every exclusion. Sets of
   rights model the C bitmask; every bool set is a valid right (the C
   `& ~VFS_RW` rejection has no counterpart by construction: nothing outside
   R/W exists). *)
type_synonym fs_right = bool
abbreviation FR :: fs_right where "FR \<equiv> True"
abbreviation FW :: fs_right where "FW \<equiv> False"

record fs_file =
  ff_size :: nat
  ff_used :: nat
  ff_owner :: nat
  ff_omode :: "fs_right set"
  ff_cap :: cptr
  ff_name :: string

record fs_fd =
  fdf_file :: nat
  fdf_off :: nat
  fdf_rights :: "fs_right set"

(* fds is curried (client, then fd) so client-A isolation is a one-line
   fun-upd fact. *)
record fs_state =
  fs_files :: "nat \<Rightarrow> fs_file option"
  fs_caps :: "cptr \<Rightarrow> cap option"
  fs_hw :: "cptr \<Rightarrow> cheri_cap"
  fs_fds :: "nat \<Rightarrow> nat \<Rightarrow> fs_fd option"

definition FS_MAX_FILES :: nat where "FS_MAX_FILES = 64"
definition FS_FDS_PER_CLIENT :: nat where "FS_FDS_PER_CLIENT = 16"
definition FS_MAX_CLIENTS :: nat where "FS_MAX_CLIENTS = 129"
definition FS_MAX_SIZE :: nat where "FS_MAX_SIZE = 1048576"

definition fs_name_char :: "char \<Rightarrow> bool" where
  "fs_name_char c \<equiv> c \<in> set ''abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-''"

definition fs_valid_name :: "string \<Rightarrow> bool" where
  "fs_valid_name n \<equiv> length n \<ge> 1 \<and> length n \<le> 31 \<and>
    hd n \<in> set ''abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._'' \<and>
    (\<forall>c \<in> set n. fs_name_char c)"

(* Backing authority: the named frame cap is live in the system cap table
   and valid against its hardware cap (tag/bounds in the CHERI model). *)
definition fs_cap_ok :: "fs_state \<Rightarrow> cptr \<Rightarrow> nat \<Rightarrow> bool" where
  "fs_cap_ok s c len \<equiv> (\<exists>k. fs_caps s c = Some k \<and> cap_valid k (fs_hw s c)) \<and> len \<le> FS_MAX_SIZE"

definition fs_allowed :: "fs_file \<Rightarrow> nat \<Rightarrow> fs_right set" where
  "fs_allowed f cli \<equiv> if ff_owner f = cli then {FR, FW} else ff_omode f"

(* Explicit file/fd ids (the C linear scans only choose free ones, which is
   not security-relevant once uniqueness is enforced). *)

definition fs_create :: "fs_state \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> string \<Rightarrow> cptr \<Rightarrow> nat \<Rightarrow> fs_right set \<Rightarrow> fs_state option" where
  "fs_create s cli F nm cp sz om =
   (if cli < FS_MAX_CLIENTS \<and> F < FS_MAX_FILES \<and> fs_valid_name nm \<and>
       1 \<le> sz \<and> sz \<le> FS_MAX_SIZE \<and> om \<subseteq> {FR, FW} \<and>
       fs_cap_ok s cp sz \<and> fs_files s F = None \<and>
       (\<forall>G f. fs_files s G = Some f \<longrightarrow> ff_name f \<noteq> nm)
    then Some (s\<lparr>fs_files := (fs_files s)(F := Some \<lparr>ff_size = sz, ff_used = 0,
        ff_owner = cli, ff_omode = om, ff_cap = cp, ff_name = nm\<rparr>) \<rparr>)
    else None)"

definition fs_open :: "fs_state \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> fs_right set \<Rightarrow> fs_state option" where
  "fs_open s cli F fd rs =
   (if cli < FS_MAX_CLIENTS \<and> F < FS_MAX_FILES \<and> fd < FS_FDS_PER_CLIENT \<and>
       rs \<noteq> {} \<and> rs \<subseteq> {FR, FW} \<and> fs_fds s cli fd = None then
      case fs_files s F of None \<Rightarrow> None
      | Some f \<Rightarrow> if rs \<subseteq> fs_allowed f cli
                 then Some (s\<lparr>fs_fds := (fs_fds s)(cli := (fs_fds s cli)(fd := Some \<lparr>fdf_file = F, fdf_off = 0, fdf_rights = rs\<rparr>)) \<rparr>)
                 else None
    else None)"

definition fs_read :: "fs_state \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> (fs_state \<times> nat) option" where
  "fs_read s cli fd n =
   (if cli < FS_MAX_CLIENTS \<and> fd < FS_FDS_PER_CLIENT then
      case fs_fds s cli fd of None \<Rightarrow> None
      | Some e \<Rightarrow>
        (if FR \<notin> fdf_rights e then None else
         case fs_files s (fdf_file e) of None \<Rightarrow> None
         | Some f \<Rightarrow> if fdf_off e > ff_used f then None
                    else let avail = ff_used f - fdf_off e; n' = min n avail in
                    Some (s\<lparr>fs_fds := (fs_fds s)(cli := (fs_fds s cli)(fd := Some (e\<lparr>fdf_off := fdf_off e + n'\<rparr>))) \<rparr>, n'))
    else None)"

definition fs_write :: "fs_state \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> (fs_state \<times> nat) option" where
  "fs_write s cli fd n =
   (if cli < FS_MAX_CLIENTS \<and> fd < FS_FDS_PER_CLIENT then
      case fs_fds s cli fd of None \<Rightarrow> None
      | Some e \<Rightarrow>
        (if FW \<notin> fdf_rights e then None else
         case fs_files s (fdf_file e) of None \<Rightarrow> None
         | Some f \<Rightarrow> if fdf_off e > ff_size f then None
                    else let avail = ff_size f - fdf_off e; n' = min n avail; used' = max (ff_used f) (fdf_off e + n') in
                    Some (s\<lparr>fs_files := (fs_files s)(fdf_file e := Some (f\<lparr>ff_used := used'\<rparr>)),
                             fs_fds := (fs_fds s)(cli := (fs_fds s cli)(fd := Some (e\<lparr>fdf_off := fdf_off e + n'\<rparr>))) \<rparr>, n'))
    else None)"

(* Seek: reposition an open fd anywhere in [0, size] (holes read as zero
   once written; the C zero-fills the gap on the extending write, which is
   size-invisible so the write theorems are untouched). No rights needed,
   like Linux lseek. wh 0/1/2 = SET/CUR/END. *)
definition fs_seek :: "fs_state \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> int \<Rightarrow> nat \<Rightarrow> fs_state option" where
  "fs_seek s cli fd off wh =
   (if cli < FS_MAX_CLIENTS \<and> fd < FS_FDS_PER_CLIENT \<and> wh \<le> 2 then
      case fs_fds s cli fd of None \<Rightarrow> None
      | Some e \<Rightarrow> (case fs_files s (fdf_file e) of None \<Rightarrow> None
         | Some f \<Rightarrow> let base = (if wh = 0 then 0 else if wh = 1 then int (fdf_off e) else int (ff_used f));
                        new = base + off
                    in if 0 \<le> new \<and> new \<le> int (ff_size f)
                       then Some (s\<lparr>fs_fds := (fs_fds s)(cli := (fs_fds s cli)(fd := Some (e\<lparr>fdf_off := nat new\<rparr>))) \<rparr>)
                       else None)
    else None)"

definition fs_close :: "fs_state \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> fs_state option" where
  "fs_close s cli fd =
   (if cli < FS_MAX_CLIENTS \<and> fd < FS_FDS_PER_CLIENT then
      case fs_fds s cli fd of None \<Rightarrow> None
      | Some _ \<Rightarrow> Some (s\<lparr>fs_fds := (fs_fds s)(cli := (fs_fds s cli)(fd := None)) \<rparr>)
    else None)"

definition fs_unlink :: "fs_state \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> fs_state option" where
  "fs_unlink s cli F =
   (if cli < FS_MAX_CLIENTS \<and> F < FS_MAX_FILES then
      case fs_files s F of None \<Rightarrow> None
      | Some f \<Rightarrow> if ff_owner f \<noteq> cli then None
                 else if (\<exists>c fd e. c < FS_MAX_CLIENTS \<and> fd < FS_FDS_PER_CLIENT \<and>
                                        fs_fds s c fd = Some e \<and> fdf_file e = F)
                      then None
                 else Some (s\<lparr>fs_files := (fs_files s)(F := None) \<rparr>)
    else None)"

(* Wellformedness: every fd names a live file with in-range offset/rights;
   every file is bounded with a legitimate owner/mode. *)

definition fs_wf :: "fs_state \<Rightarrow> bool" where
  "fs_wf s \<equiv> (\<forall>c fd e. c < FS_MAX_CLIENTS \<and> fd < FS_FDS_PER_CLIENT \<and>
     fs_fds s c fd = Some e \<longrightarrow>
     fdf_file e < FS_MAX_FILES \<and> (\<exists>f. fs_files s (fdf_file e) = Some f \<and>
       fdf_off e \<le> ff_size f \<and> (\<forall>x \<in> fdf_rights e. x = FR \<or> x = FW))) \<and>
   (\<forall>F f. F < FS_MAX_FILES \<and> fs_files s F = Some f \<longrightarrow>
     ff_used f \<le> ff_size f \<and> ff_size f \<le> FS_MAX_SIZE \<and>
     (\<forall>x \<in> ff_omode f. x = FR \<or> x = FW) \<and> ff_owner f < FS_MAX_CLIENTS)"

(* ---- isolation: no op touches another client's fd table ---- *)

theorem create_other_fds:
  "fs_create s B F nm cp sz om = Some s' \<Longrightarrow> A \<noteq> B \<Longrightarrow> fs_fds s' A = fs_fds s A"
  unfolding fs_create_def by (auto split: if_splits option.splits)

theorem open_other_fds:
  "fs_open s B F fd rs = Some s' \<Longrightarrow> A \<noteq> B \<Longrightarrow> fs_fds s' A = fs_fds s A"
  unfolding fs_open_def by (auto split: if_splits option.splits)

theorem read_other_fds:
  "fs_read s B fd n = Some (s', n') \<Longrightarrow> A \<noteq> B \<Longrightarrow> fs_fds s' A = fs_fds s A"
  unfolding fs_read_def by (auto split: if_splits option.splits simp: Let_def)

theorem write_other_fds:
  "fs_write s B fd n = Some (s', n') \<Longrightarrow> A \<noteq> B \<Longrightarrow> fs_fds s' A = fs_fds s A"
  unfolding fs_write_def by (auto split: if_splits option.splits simp: Let_def)

theorem close_other_fds:
  "fs_close s B fd = Some s' \<Longrightarrow> A \<noteq> B \<Longrightarrow> fs_fds s' A = fs_fds s A"
  unfolding fs_close_def by (auto split: if_splits option.splits)

theorem unlink_other_fds:
  "fs_unlink s B F = Some s' \<Longrightarrow> fs_fds s' = fs_fds s"
  unfolding fs_unlink_def by (auto split: if_splits option.splits)

(* Unlink revokes nothing but the file: every fd entry survives verbatim. *)
theorem unlink_fds_kept:
  "fs_unlink s B F = Some s' \<Longrightarrow> \<forall>c fd. fs_fds s' c fd = fs_fds s c fd"
  unfolding fs_unlink_def by (auto split: if_splits option.splits)

theorem seek_other_fds:
  "fs_seek s B fd off wh = Some s' \<Longrightarrow> A \<noteq> B \<Longrightarrow> fs_fds s' A = fs_fds s A"
  unfolding fs_seek_def by (auto split: if_splits option.splits simp: Let_def)

(* ---- rights confinement ---- *)

theorem read_needs_R:
  "fs_read s cli fd n = Some (s', n') \<Longrightarrow>
   \<exists>e. fs_fds s cli fd = Some e \<and> FR \<in> fdf_rights e"
  unfolding fs_read_def by (auto split: if_splits option.splits)

theorem write_needs_W:
  "fs_write s cli fd n = Some (s', n') \<Longrightarrow>
   \<exists>e. fs_fds s cli fd = Some e \<and> FW \<in> fdf_rights e"
  unfolding fs_write_def by (auto split: if_splits option.splits)

theorem open_subset_allowed:
  "fs_open s cli F fd rs = Some s' \<Longrightarrow>
   \<exists>f. fs_files s F = Some f \<and> rs \<subseteq> fs_allowed f cli"
  unfolding fs_open_def by (auto split: if_splits option.splits)

(* Clamped increments never overflow: ≤-premise so dest-matching needs no
   negation juggling. Proved once by arith, applied forward everywhere. *)
lemma min_add_le: "off \<le> (sz::nat) \<Longrightarrow> off + min n (sz - off) \<le> sz"
  by arith

(* Read-quantum arithmetic end-to-end, single-hop dest: takes the U1/U2
   Horns themselves as premises (all occur verbatim as branch hypotheses),
   so forward firing needs no chaining and no wf. *)
lemma read_arith2:
  "\<lbrakk>\<And>c fd e. \<lbrakk>c < FS_MAX_CLIENTS; fd < FS_FDS_PER_CLIENT;
      fs_fds s c fd = Some e\<rbrakk>
     \<Longrightarrow> fdf_file e < FS_MAX_FILES \<and>
        (\<exists>f. fs_files s (fdf_file e) = Some f \<and> fdf_off e \<le> ff_size f);
    \<And>Fa f. \<lbrakk>Fa < FS_MAX_FILES; fs_files s Fa = Some f\<rbrakk>
     \<Longrightarrow> ff_used f \<le> ff_size f \<and> ff_size f \<le> FS_MAX_SIZE \<and> ff_owner f < FS_MAX_CLIENTS;
    c < FS_MAX_CLIENTS; fd < FS_FDS_PER_CLIENT;
    fs_fds s c fd = Some e; fs_files s (fdf_file e) = Some f;
    \<not> ff_used f < fdf_off e\<rbrakk>
   \<Longrightarrow> fdf_off e + min n (ff_used f - fdf_off e) \<le> ff_size f"
proof -
  assume H1: "\<And>c fd e. \<lbrakk>c < FS_MAX_CLIENTS; fd < FS_FDS_PER_CLIENT;
      fs_fds s c fd = Some e\<rbrakk>
     \<Longrightarrow> fdf_file e < FS_MAX_FILES \<and>
        (\<exists>f. fs_files s (fdf_file e) = Some f \<and> fdf_off e \<le> ff_size f)"
     and H2: "\<And>Fa f. \<lbrakk>Fa < FS_MAX_FILES; fs_files s Fa = Some f\<rbrakk>
     \<Longrightarrow> ff_used f \<le> ff_size f \<and> ff_size f \<le> FS_MAX_SIZE \<and> ff_owner f < FS_MAX_CLIENTS"
     and b1: "c < FS_MAX_CLIENTS" and b2: "fd < FS_FDS_PER_CLIENT"
     and feq: "fs_fds s c fd = Some e" and feq2: "fs_files s (fdf_file e) = Some f"
     and nle: "\<not> ff_used f < fdf_off e"
  from H1 b1 b2 feq have fa64: "fdf_file e < FS_MAX_FILES" by auto
  from H2 fa64 feq2 have usedle: "ff_used f \<le> ff_size f" by auto
  from nle have le: "fdf_off e \<le> ff_used f" by (simp add: not_less)
  from le usedle show "fdf_off e + min n (ff_used f - fdf_off e) \<le> ff_size f"
    by arith
qed

(* ---- bounds safety (nat subtraction saturates: no wrap possible) ---- *)

theorem read_bounded:
  "fs_read s cli fd n = Some (s', n') \<Longrightarrow>
   \<exists>e f. fs_fds s cli fd = Some e \<and> fs_files s (fdf_file e) = Some f \<and>
     n' = min n (ff_used f - fdf_off e) \<and> fdf_off e + n' \<le> ff_used f"
  unfolding fs_read_def
  by (auto split: if_splits option.splits simp: Let_def)

theorem write_bounded:
  "fs_write s cli fd n = Some (s', n') \<Longrightarrow>
   \<exists>e f. fs_fds s cli fd = Some e \<and> fs_files s (fdf_file e) = Some f \<and>
     n' = min n (ff_size f - fdf_off e) \<and> fdf_off e + n' \<le> ff_size f"
  unfolding fs_write_def
  by (auto split: if_splits option.splits simp: Let_def)

theorem seek_bounded:
  "fs_seek s cli fd off wh = Some s' \<Longrightarrow>
   \<exists>e f noff. fs_fds s cli fd = Some e \<and> fs_files s (fdf_file e) = Some f \<and>
     fs_fds s' cli fd = Some (e\<lparr>fdf_off := noff\<rparr>) \<and> noff \<le> ff_size f"
  unfolding fs_seek_def
  by (auto split: if_splits option.splits simp: Let_def)

(* ---- ownership ---- *)

theorem unlink_owner_only:
  "fs_unlink s cli F = Some s' \<Longrightarrow>
   \<exists>f. fs_files s F = Some f \<and> ff_owner f = cli"
  unfolding fs_unlink_def by (auto split: if_splits option.splits)

theorem unlink_no_open:
  "fs_unlink s cli F = Some s' \<Longrightarrow>
   \<forall>c fd e. c < FS_MAX_CLIENTS \<and> fd < FS_FDS_PER_CLIENT \<and> fs_fds s c fd = Some e \<longrightarrow> fdf_file e \<noteq> F"
  unfolding fs_unlink_def by (auto split: if_splits option.splits)

theorem create_owner:
  "fs_create s cli F nm cp sz om = Some s' \<Longrightarrow>
   \<exists>f. fs_files s' F = Some f \<and> ff_owner f = cli \<and> ff_used f = 0"
  unfolding fs_create_def by (auto split: if_splits option.splits)

theorem create_backed:
  "fs_create s cli F nm cp sz om = Some s' \<Longrightarrow> fs_cap_ok s cp sz"
  unfolding fs_create_def fs_cap_ok_def by (auto split: if_splits option.splits)

(* ---- wellformedness preservation ----
   Shared forward facts (blast-proved): fd entries always resolve, files
   stay bounded. Stated with atomic record terms so automation cannot
   normalize them away. *)

theorem wf_create:
  "fs_wf s \<Longrightarrow> fs_create s cli F nm cp sz om = Some s' \<Longrightarrow> fs_wf s'"
proof -
  assume wf: "fs_wf s" and h: "fs_create s cli F nm cp sz om = Some s'"
  from h have seq: "s' = s\<lparr>fs_files := (fs_files s)(F := Some \<lparr>ff_size = sz, ff_used = 0,
      ff_owner = cli, ff_omode = om, ff_cap = cp, ff_name = nm\<rparr>) \<rparr>"
    unfolding fs_create_def by (auto split: if_splits option.splits)
  from h have G: "cli < FS_MAX_CLIENTS \<and> F < FS_MAX_FILES \<and> 1 \<le> sz \<and> sz \<le> FS_MAX_SIZE \<and>
      om \<subseteq> {FR, FW} \<and> fs_files s F = None"
    unfolding fs_create_def by (auto split: if_splits option.splits)
  from wf have U1: "\<And>c fd e. \<lbrakk>c < FS_MAX_CLIENTS; fd < FS_FDS_PER_CLIENT;
      fs_fds s c fd = Some e\<rbrakk> \<Longrightarrow>
      fdf_file e < FS_MAX_FILES \<and> (\<exists>f. fs_files s (fdf_file e) = Some f \<and> fdf_off e \<le> ff_size f)"
    unfolding fs_wf_def FS_MAX_CLIENTS_def FS_FDS_PER_CLIENT_def FS_MAX_FILES_def
    by blast
  from wf have U2: "\<And>Fa f. \<lbrakk>Fa < FS_MAX_FILES; fs_files s Fa = Some f\<rbrakk> \<Longrightarrow>
      ff_used f \<le> ff_size f \<and> ff_size f \<le> FS_MAX_SIZE \<and>
      (\<forall>x \<in> ff_omode f. x = FR \<or> x = FW) \<and> ff_owner f < FS_MAX_CLIENTS"
    unfolding fs_wf_def FS_MAX_FILES_def FS_MAX_SIZE_def FS_MAX_CLIENTS_def
    by blast
  from U1 U2 G show "fs_wf s'"
    unfolding seq fs_wf_def
    by (auto dest: U1 U2)
qed

theorem wf_open:
  "fs_wf s \<Longrightarrow> fs_open s cli F fd rs = Some s' \<Longrightarrow> fs_wf s'"
proof -
  assume wf: "fs_wf s" and h: "fs_open s cli F fd rs = Some s'"
  from h have seq: "s' = s\<lparr>fs_fds := (fs_fds s)(cli := (fs_fds s cli)(fd := Some \<lparr>fdf_file = F, fdf_off = 0, fdf_rights = rs\<rparr>))\<rparr>"
    unfolding fs_open_def by (auto split: if_splits option.splits)
  from h have G: "cli < FS_MAX_CLIENTS \<and> F < FS_MAX_FILES \<and> fd < FS_FDS_PER_CLIENT \<and>
      rs \<noteq> {} \<and> rs \<subseteq> {FR, FW} \<and> fs_fds s cli fd = None \<and> (\<exists>f. fs_files s F = Some f)"
    unfolding fs_open_def by (auto split: if_splits option.splits)
  from wf have U1: "\<And>c fd e. \<lbrakk>c < FS_MAX_CLIENTS; fd < FS_FDS_PER_CLIENT;
      fs_fds s c fd = Some e\<rbrakk> \<Longrightarrow>
      fdf_file e < FS_MAX_FILES \<and> (\<exists>f. fs_files s (fdf_file e) = Some f \<and> fdf_off e \<le> ff_size f)"
    unfolding fs_wf_def FS_MAX_CLIENTS_def FS_FDS_PER_CLIENT_def FS_MAX_FILES_def
    by blast
  from wf have U2: "\<And>Fa f. \<lbrakk>Fa < FS_MAX_FILES; fs_files s Fa = Some f\<rbrakk> \<Longrightarrow>
      ff_used f \<le> ff_size f \<and> ff_size f \<le> FS_MAX_SIZE \<and>
      (\<forall>x \<in> ff_omode f. x = FR \<or> x = FW) \<and> ff_owner f < FS_MAX_CLIENTS"
    unfolding fs_wf_def FS_MAX_FILES_def FS_MAX_SIZE_def FS_MAX_CLIENTS_def
    by blast
  from U1 U2 G show "fs_wf s'"
    unfolding seq fs_wf_def
    by (auto dest: U1 U2)
qed

theorem wf_read:
  "fs_wf s \<Longrightarrow> fs_read s cli fd n = Some (s', n') \<Longrightarrow> fs_wf s'"
proof -
  assume wf: "fs_wf s" and h: "fs_read s cli fd n = Some (s', n')"
  from wf have U1: "\<And>c fd e. \<lbrakk>c < FS_MAX_CLIENTS; fd < FS_FDS_PER_CLIENT;
      fs_fds s c fd = Some e\<rbrakk> \<Longrightarrow>
      fdf_file e < FS_MAX_FILES \<and> (\<exists>f. fs_files s (fdf_file e) = Some f \<and> fdf_off e \<le> ff_size f)"
    unfolding fs_wf_def FS_MAX_CLIENTS_def FS_FDS_PER_CLIENT_def FS_MAX_FILES_def
    by blast
  from wf have U2: "\<And>Fa f. \<lbrakk>Fa < FS_MAX_FILES; fs_files s Fa = Some f\<rbrakk> \<Longrightarrow>
      ff_used f \<le> ff_size f \<and> ff_size f \<le> FS_MAX_SIZE \<and>
      (\<forall>x \<in> ff_omode f. x = FR \<or> x = FW) \<and> ff_owner f < FS_MAX_CLIENTS"
    unfolding fs_wf_def FS_MAX_FILES_def FS_MAX_SIZE_def FS_MAX_CLIENTS_def
    by blast
  from U1 U2 h have goalU: "(\<forall>c fd e. c < FS_MAX_CLIENTS \<and> fd < FS_FDS_PER_CLIENT \<and>
     fs_fds s' c fd = Some e \<longrightarrow>
     fdf_file e < FS_MAX_FILES \<and> (\<exists>f. fs_files s' (fdf_file e) = Some f \<and> fdf_off e \<le> ff_size f \<and>
       (\<forall>x \<in> fdf_rights e. x = FR \<or> x = FW))) \<and>
   (\<forall>F f. F < FS_MAX_FILES \<and> fs_files s' F = Some f \<longrightarrow>
     ff_used f \<le> ff_size f \<and> ff_size f \<le> FS_MAX_SIZE \<and>
     (\<forall>x \<in> ff_omode f. x = FR \<or> x = FW) \<and> ff_owner f < FS_MAX_CLIENTS)"
    unfolding fs_read_def
    apply (auto dest: U1 U2 simp: Let_def split: if_splits option.splits)
    apply (rule read_arith2)
    apply assumption+
    done
  from goalU show "fs_wf s'"
    unfolding fs_wf_def
    by auto
qed

theorem wf_write:
  "fs_wf s \<Longrightarrow> fs_write s cli fd n = Some (s', n') \<Longrightarrow> fs_wf s'"
proof -
  assume wf: "fs_wf s" and h: "fs_write s cli fd n = Some (s', n')"
  from wf have U1: "\<And>c fd e. \<lbrakk>c < FS_MAX_CLIENTS; fd < FS_FDS_PER_CLIENT;
      fs_fds s c fd = Some e\<rbrakk> \<Longrightarrow>
      fdf_file e < FS_MAX_FILES \<and> (\<exists>f. fs_files s (fdf_file e) = Some f \<and> fdf_off e \<le> ff_size f)"
    unfolding fs_wf_def FS_MAX_CLIENTS_def FS_FDS_PER_CLIENT_def FS_MAX_FILES_def
    by blast
  from wf have U2: "\<And>Fa f. \<lbrakk>Fa < FS_MAX_FILES; fs_files s Fa = Some f\<rbrakk> \<Longrightarrow>
      ff_used f \<le> ff_size f \<and> ff_size f \<le> FS_MAX_SIZE \<and>
      (\<forall>x \<in> ff_omode f. x = FR \<or> x = FW) \<and> ff_owner f < FS_MAX_CLIENTS"
    unfolding fs_wf_def FS_MAX_FILES_def FS_MAX_SIZE_def FS_MAX_CLIENTS_def
    by blast
  from h obtain e0 where old: "fs_fds s cli fd = Some e0"
    unfolding fs_write_def by (auto split: if_splits option.splits)
  from h old obtain f0 where
      file0: "fs_files s (fdf_file e0) = Some f0"
    unfolding fs_write_def by (auto split: if_splits option.splits)
  from h old file0 have G0: "cli < FS_MAX_CLIENTS \<and> fd < FS_FDS_PER_CLIENT \<and> FW \<in> fdf_rights e0 \<and>
               fdf_off e0 \<le> ff_size f0 \<and> fdf_file e0 < FS_MAX_FILES"
    unfolding fs_write_def by (auto dest: U1 split: if_splits option.splits)
  from h old file0 have seq: "s' = s\<lparr>fs_files := (fs_files s)(fdf_file e0 := Some (f0\<lparr>ff_used := max (ff_used f0) (fdf_off e0 + min n (ff_size f0 - fdf_off e0))\<rparr>)),
                   fs_fds := (fs_fds s)(cli := (fs_fds s cli)(fd := Some (e0\<lparr>fdf_off := fdf_off e0 + min n (ff_size f0 - fdf_off e0)\<rparr>)))\<rparr>"
    unfolding fs_write_def by (auto split: if_splits option.splits simp: Let_def)
  from U1 U2 seq old file0 G0 show "fs_wf s'"
    unfolding seq fs_wf_def
    by (auto dest: U1 U2 min_add_le)
qed

theorem write_used_capped:
  "fs_wf s \<Longrightarrow> fs_write s cli fd n = Some (s', n') \<Longrightarrow>
   \<forall>F f'. F < FS_MAX_FILES \<and> fs_files s' F = Some f' \<longrightarrow> ff_used f' \<le> ff_size f'"
proof -
  assume wf: "fs_wf s" and h: "fs_write s cli fd n = Some (s', n')"
  from wf_write[OF wf h, unfolded fs_wf_def FS_MAX_FILES_def] show
      "\<forall>F f'. F < FS_MAX_FILES \<and> fs_files s' F = Some f' \<longrightarrow> ff_used f' \<le> ff_size f'"
    unfolding FS_MAX_FILES_def
    by auto
qed

(* Bridge for seek arithmetic: the model checks bounds on ints, the state
   stores nats. Closed once by arith, used as an intro rule. *)
lemma nat_le_of_int: "0 \<le> (x::int) \<Longrightarrow> x \<le> int n \<Longrightarrow> nat x \<le> n"
  by arith

theorem wf_seek:
  "fs_wf s \<Longrightarrow> fs_seek s cli fd off wh = Some s' \<Longrightarrow> fs_wf s'"
proof -
  assume wf: "fs_wf s" and h: "fs_seek s cli fd off wh = Some s'"
  from h have G: "cli < FS_MAX_CLIENTS \<and> fd < FS_FDS_PER_CLIENT \<and> wh \<le> 2"
    unfolding fs_seek_def by (auto split: if_splits option.splits simp: Let_def)
  from h G obtain e0 where old: "fs_fds s cli fd = Some e0"
    unfolding fs_seek_def by (auto split: if_splits option.splits simp: Let_def)
  from h G old obtain f0 where
      file0: "fs_files s (fdf_file e0) = Some f0"
    unfolding fs_seek_def by (auto split: if_splits option.splits simp: Let_def)
  (* Syntactic extraction only (no arithmetic in the conclusions): the new
     offset is `nat new` for a branch-provided int `new` with its bounds. *)
  from h G old file0 obtain nw new where
      seq: "s' = s\<lparr>fs_fds := (fs_fds s)(cli := (fs_fds s cli)(fd := Some (e0\<lparr>fdf_off := nw\<rparr>)))\<rparr>"
      and nwdef: "nw = nat new"
      and nonneg: "(0::int) \<le> new"
      and bnd: "new \<le> int (ff_size f0)"
    unfolding fs_seek_def by (auto split: if_splits option.splits simp: Let_def)
  from nat_le_of_int[OF nonneg bnd] have le: "nw \<le> ff_size f0"
    unfolding nwdef by simp
  from wf have U1: "\<And>c fd e. \<lbrakk>c < FS_MAX_CLIENTS; fd < FS_FDS_PER_CLIENT;
      fs_fds s c fd = Some e\<rbrakk> \<Longrightarrow>
      fdf_file e < FS_MAX_FILES \<and> (\<exists>f. fs_files s (fdf_file e) = Some f \<and> fdf_off e \<le> ff_size f)"
    unfolding fs_wf_def FS_MAX_CLIENTS_def FS_FDS_PER_CLIENT_def FS_MAX_FILES_def
    by blast
  from wf have U2: "\<And>Fa f. \<lbrakk>Fa < FS_MAX_FILES; fs_files s Fa = Some f\<rbrakk> \<Longrightarrow>
      ff_used f \<le> ff_size f \<and> ff_size f \<le> FS_MAX_SIZE \<and>
      (\<forall>x \<in> ff_omode f. x = FR \<or> x = FW) \<and> ff_owner f < FS_MAX_CLIENTS"
    unfolding fs_wf_def FS_MAX_FILES_def FS_MAX_SIZE_def FS_MAX_CLIENTS_def
    by blast
  from U1 U2 seq old file0 G le show "fs_wf s'"
    unfolding seq fs_wf_def
    by (auto dest: U1 U2)
qed

theorem wf_close:
  "fs_wf s \<Longrightarrow> fs_close s cli fd = Some s' \<Longrightarrow> fs_wf s'"
proof -
  assume wf: "fs_wf s" and h: "fs_close s cli fd = Some s'"
  from h have seq: "s' = s\<lparr>fs_fds := (fs_fds s)(cli := (fs_fds s cli)(fd := None))\<rparr>"
    unfolding fs_close_def by (auto split: if_splits option.splits)
  from h have G: "cli < FS_MAX_CLIENTS \<and> fd < FS_FDS_PER_CLIENT"
    unfolding fs_close_def by (auto split: if_splits option.splits)
  from wf have U1: "\<And>c fd e. \<lbrakk>c < FS_MAX_CLIENTS; fd < FS_FDS_PER_CLIENT;
      fs_fds s c fd = Some e\<rbrakk> \<Longrightarrow>
      fdf_file e < FS_MAX_FILES \<and> (\<exists>f. fs_files s (fdf_file e) = Some f \<and> fdf_off e \<le> ff_size f)"
    unfolding fs_wf_def FS_MAX_CLIENTS_def FS_FDS_PER_CLIENT_def FS_MAX_FILES_def
    by blast
  from wf have U2: "\<And>Fa f. \<lbrakk>Fa < FS_MAX_FILES; fs_files s Fa = Some f\<rbrakk> \<Longrightarrow>
      ff_used f \<le> ff_size f \<and> ff_size f \<le> FS_MAX_SIZE \<and>
      (\<forall>x \<in> ff_omode f. x = FR \<or> x = FW) \<and> ff_owner f < FS_MAX_CLIENTS"
    unfolding fs_wf_def FS_MAX_FILES_def FS_MAX_SIZE_def FS_MAX_CLIENTS_def
    by blast
  from U1 U2 G show "fs_wf s'"
    unfolding seq fs_wf_def
    by (auto dest: U1 U2)
qed

theorem wf_unlink:
  "fs_wf s \<Longrightarrow> fs_unlink s cli F = Some s' \<Longrightarrow> fs_wf s'"
proof -
  assume wf: "fs_wf s" and h: "fs_unlink s cli F = Some s'"
  from h have seq: "s' = s\<lparr>fs_files := (fs_files s)(F := None)\<rparr>"
    unfolding fs_unlink_def by (auto split: if_splits option.splits)
  from h have G: "cli < FS_MAX_CLIENTS \<and> F < FS_MAX_FILES \<and>
      (\<forall>c fd e. c < FS_MAX_CLIENTS \<and> fd < FS_FDS_PER_CLIENT \<and>
        fs_fds s c fd = Some e \<longrightarrow> fdf_file e \<noteq> F)"
    unfolding fs_unlink_def by (auto split: if_splits option.splits)
  from wf have U1: "\<And>c fd e. \<lbrakk>c < FS_MAX_CLIENTS; fd < FS_FDS_PER_CLIENT;
      fs_fds s c fd = Some e\<rbrakk> \<Longrightarrow>
      fdf_file e < FS_MAX_FILES \<and> (\<exists>f. fs_files s (fdf_file e) = Some f \<and> fdf_off e \<le> ff_size f)"
    unfolding fs_wf_def FS_MAX_CLIENTS_def FS_FDS_PER_CLIENT_def FS_MAX_FILES_def
    by blast
  from wf have U2: "\<And>Fa f. \<lbrakk>Fa < FS_MAX_FILES; fs_files s Fa = Some f\<rbrakk> \<Longrightarrow>
      ff_used f \<le> ff_size f \<and> ff_size f \<le> FS_MAX_SIZE \<and>
      (\<forall>x \<in> ff_omode f. x = FR \<or> x = FW) \<and> ff_owner f < FS_MAX_CLIENTS"
    unfolding fs_wf_def FS_MAX_FILES_def FS_MAX_SIZE_def FS_MAX_CLIENTS_def
    by blast
  from U1 U2 G show "fs_wf s'"
    unfolding seq fs_wf_def
    by (auto dest: U1 U2)
qed

end
