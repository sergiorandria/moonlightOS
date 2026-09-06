theory IOMMU_Verification
imports Moonlight_A
begin

consts dma_request :: "nat \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> bool"
consts dma_fault :: "abs_state \<Rightarrow> bool"

theorem iommu_isolation:
  assumes "iommu_wellformed s" and "iommu_allows s dev paddr" and "dev \<noteq> dev'"
  shows "\<not> iommu_allows s dev' paddr"
  using assms unfolding iommu_allows_def iommu_wellformed_def
  by (blast)

theorem dma_confinement:
  assumes "invs s" and "dma_request dev paddr len" and "\<not> iommu_allows (abs_iommu s) dev paddr \<Longrightarrow> dma_fault s"
  shows "iommu_allows (abs_iommu s) dev paddr \<or> dma_fault s"
  using assms by blast

end
