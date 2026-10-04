/* userspace/gui/display.h - Display-server RPC tags (userspace only).
 * Kernel IPC is untyped words; these names live with the gui ELF. */
#ifndef GUI_DISPLAY_H
#define GUI_DISPLAY_H

#define GUI_RPC_FILL 6u
#define GUI_RPC_SURF_CREATE 7u
#define GUI_RPC_SURF_DESTROY 8u
#define GUI_RPC_COMPOSE 9u
#define GUI_RPC_CURSOR 10u /* stub: not served yet */
#define GUI_RPC_WM_CREATE 11u
#define GUI_RPC_WM_DESTROY 12u

#define GUI_R_OK 0
#define GUI_R_DENY (-1)

#endif /* GUI_DISPLAY_H */
