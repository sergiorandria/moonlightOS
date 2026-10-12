/* tests/test_render_perf.c - host vectors for GUI+console render fast paths.
 * Refs: Bochs VGA 800x600x32, 8x16 cells (100x37); BusyBox-style line
 * discipline owns text, GUI owns fb; kernel/ipc.h 32-deep queue.
 */
#include "../userspace/gui/rect.h"
#include <stdint.h>
#include <stdio.h>

#define CHECK(c)                                                               \
  do {                                                                         \
    if (!(c)) {                                                                \
      printf("FAIL line %d: %s\n", __LINE__, #c);                              \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  uint32_t cx, cy, cw, ch;

  /* clip: in-bounds passes through */
  CHECK(rect_clip_fill(10u, 20u, 100u, 50u, &cx, &cy, &cw, &ch) == 1);
  CHECK(cx == 10u && cy == 20u && cw == 100u && ch == 50u);

  /* clip: right/bottom overhang clamps to 800x600 */
  CHECK(rect_clip_fill(790u, 590u, 20u, 20u, &cx, &cy, &cw, &ch) == 1);
  CHECK(cx == 790u && cy == 590u && cw == 10u && ch == 10u);

  /* clip: origin OOB / zero size rejects */
  CHECK(rect_clip_fill(800u, 0u, 10u, 10u, &cx, &cy, &cw, &ch) == 0);
  CHECK(rect_clip_fill(0u, 0u, 0u, 10u, &cx, &cy, &cw, &ch) == 0);
  CHECK(rect_clip_fill(0xFFFFFF00u, 0u, 0x200u, 1u, &cx, &cy, &cw, &ch) == 0);

  /* scroll: 1 line shifts 600-16 rows, clears bottom 16 rows */
  {
    uint32_t move_rows, clear_y, clear_h;
    CHECK(scroll_region_n(1u, 16u, 600u, &move_rows, &clear_y, &clear_h) == 1);
    CHECK(move_rows == 584u && clear_y == 584u && clear_h == 16u);
  }
  /* scroll: N lines single pass; clamp over-tall to full frame */
  {
    uint32_t move_rows, clear_y, clear_h;
    CHECK(scroll_region_n(3u, 16u, 600u, &move_rows, &clear_y, &clear_h) == 1);
    CHECK(move_rows == 552u && clear_y == 552u && clear_h == 48u);
    CHECK(scroll_region_n(99u, 16u, 600u, &move_rows, &clear_y, &clear_h) == 1);
    CHECK(move_rows == 0u && clear_y == 0u && clear_h == 600u);
    CHECK(scroll_region_n(0u, 16u, 600u, &move_rows, &clear_y, &clear_h) == 0);
  }

  /* glyph precondition: 100x37 cells */
  CHECK(glyph_cell_ok(0u, 0u, 100u, 37u) == 1);
  CHECK(glyph_cell_ok(99u, 36u, 100u, 37u) == 1);
  CHECK(glyph_cell_ok(100u, 0u, 100u, 37u) == 0);
  CHECK(glyph_cell_ok(0u, 37u, 100u, 37u) == 0);

  printf("PASS: test_render_perf\n");
  return 0;
}
