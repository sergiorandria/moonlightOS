theory CacheColoring
imports Main
begin

definition num_colors :: nat where "num_colors = 16"
definition colors_per_partition :: nat where "colors_per_partition = 2"

definition color_of :: "nat \<Rightarrow> nat" where "color_of paddr = (paddr div 4096) mod num_colors"
definition partition_color :: "nat \<Rightarrow> nat" where "partition_color p = (p * colors_per_partition) mod num_colors"

definition color_is_valid :: "nat \<Rightarrow> nat \<Rightarrow> bool" where
  "color_is_valid part col \<longleftrightarrow> col = partition_color part \<or> col = partition_color part + 1"

lemma color_disjoint:
  "part1 \<noteq> part2 \<Longrightarrow> partition_color part1 \<noteq> partition_color part2"
  sorry

theorem no_cache_interference:
  "color_is_valid p col1 \<Longrightarrow> color_is_valid p col2 \<Longrightarrow> color_of paddr1 = col1 \<Longrightarrow> color_of paddr2 = col2 \<Longrightarrow>
   p \<noteq> q \<Longrightarrow> \<not> color_is_valid q col1"
  sorry

end
