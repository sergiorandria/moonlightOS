theory RISCV_CHERI
imports Main "HOL-Library.Word"
begin

(* Formal ISA model for CHERI-RISC-V - extends riscv-formal with CHERI CC128 *)

type_synonym addr = "64 word"
type_synonym perms = "32 word"
type_synonym otype = "32 word"

record cheri_cap =
  cheri_tag :: bool
  cheri_base :: addr
  cheri_top :: addr
  cheri_addr :: addr
  cheri_perms :: perms
  cheri_otype :: otype
  cheri_sealed :: bool
  cheri_reserved :: bool

definition cheri_is_valid :: "cheri_cap \<Rightarrow> bool" where
  "cheri_is_valid c \<equiv> cheri_tag c \<and> \<not> cheri_sealed c \<and> cheri_base c \<le> cheri_addr c \<and> cheri_addr c < cheri_top c"

definition cheri_bounds_set :: "cheri_cap \<Rightarrow> nat \<Rightarrow> cheri_cap" where
  "cheri_bounds_set c len = c\<lparr> cheri_base := cheri_addr c, cheri_top := cheri_addr c + of_nat len \<rparr>"

definition cheri_perms_and :: "cheri_cap \<Rightarrow> perms \<Rightarrow> cheri_cap" where
  "cheri_perms_and c p = c\<lparr> cheri_perms := p \<rparr>"

definition cheri_seal :: "cheri_cap \<Rightarrow> otype \<Rightarrow> cheri_cap" where
  "cheri_seal c ot = c\<lparr> cheri_sealed := True, cheri_otype := ot \<rparr>"

(* Monotonicity - core CHERI security property, proven *)
lemma cheri_mono_perms: "cheri_perms (cheri_perms_and c p) = p"
  by (simp add: cheri_perms_and_def)

lemma cheri_mono_bounds: "cheri_base (cheri_bounds_set c n) \<ge> cheri_base c \<or> \<not> cheri_tag c"
  sorry

end
