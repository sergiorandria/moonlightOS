theory IOMMU_Verification
imports Moonlight_A
begin

definition iommu_allows :: "iommu_state \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool" where
  "iommu_allows iommu dev paddr = (\<exists>w. w \<in> windows iommu \<and> dev = dev_id w \<and> paddr \<in> range w)"

theorem iommu_isolation:
  "iommu_allows s dev paddr \<Longrightarrow> dev \<noteq> dev' \<Longrightarrow> \<not> iommu_allows s dev' paddr"
  sorry

theorem dma_confinement:
  "invs s \<Longrightarrow> dma_request dev paddr len \<Longrightarrow> iommu_allows (iommu s) dev paddr \<or> dma_fault s"
  sorry

end
