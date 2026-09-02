theory IOMMU_Verification
imports Moonlight_A
begin

typedecl iommu_state
type_synonym window = nat
consts windows :: "iommu_state \<Rightarrow> window set"
consts dev_id :: "window \<Rightarrow> nat"
consts range :: "window \<Rightarrow> nat set"
consts dma_request :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool"
consts abs_iommu :: "abs_state \<Rightarrow> iommu_state"
consts dma_fault :: "abs_state \<Rightarrow> bool"

definition iommu_allows :: "iommu_state \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool" where
  "iommu_allows iommu dev paddr = (\<exists>w. w \<in> windows iommu \<and> dev = dev_id w \<and> paddr \<in> range w)"

theorem iommu_isolation:
  "iommu_allows s dev paddr \<Longrightarrow> dev \<noteq> dev' \<Longrightarrow> \<not> iommu_allows s dev' paddr"
  sorry

theorem dma_confinement:
  "invs s \<Longrightarrow> dma_request dev paddr len \<Longrightarrow> iommu_allows (abs_iommu s) dev paddr \<or> dma_fault s"
  sorry

end
