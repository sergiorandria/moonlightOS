/* kernel/uentry.h - symbols shared between the S-mode kernel (kboot.c)
 * and the U-mode demo image (user.c).
 *
 * One declaration site, so both translation units are checked against it
 * (-Wmissing-prototypes / -Wmissing-variable-declarations stay clean).
 * Declarations only: user.c may not define globals through this header,
 * see the Stage-1 constraint at the top of user.c. */
#ifndef V2_UENTRY_H
#define V2_UENTRY_H

#include <stdint.h>

void user_a_main(void);
void user_b_main(void);
void mem_server_main(void);
void test_cap_thread(void);
void user_stacks_init(void);

extern uintptr_t ustack_a_top, ustack_b_top, ustack_m_top, ustack_cap_top;
extern uintptr_t ustack_qrexec_top, ustack_adminvm_top;
extern uintptr_t ustack_fw_top, ustack_net_top;
extern uintptr_t ustack_vault_top, ustack_crypt_top;
extern uintptr_t ustack_gui_top;

#endif /* V2_UENTRY_H */
