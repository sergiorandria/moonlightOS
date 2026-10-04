/*
 * tty.h - TTY Service Interface
 *
 * The TTY service implements terminal line discipline and session management.
 * Responsibilities:
 *   - Line editing (backspace, line buffering, canonical mode)
 *   - Character echo
 *   - Signal generation (Ctrl+C, Ctrl+Z)
 *   - Job control
 *   - Raw vs canonical mode
 *   - Multiple TTY sessions (one per virtual console)
 */

#ifndef TTY_H
#define TTY_H

#include <stdint.h>
#include "services/ipc_protocol.h"

/* TTY configuration */
#define TTY_COUNT           12      /* Number of TTYs (one per console) */
#define TTY_INPUT_BUF_SIZE  1024    /* Input buffer size */
#define TTY_LINE_BUF_SIZE   256     /* Line buffer for canonical mode */

/* Maximum readers that can block waiting for input on one TTY at a time */
#define TTY_MAX_PENDING_READERS 4

/* TTY flags */
#define TTY_FLAG_ECHO       (1 << 0)  /* Echo input characters */
#define TTY_FLAG_CANON      (1 << 1)  /* Canonical mode (line buffering) */
#define TTY_FLAG_RAW        (1 << 2)  /* Raw mode (no processing) */
#define TTY_FLAG_OPEN       (1 << 3)  /* TTY is open by a process */

/* Special characters */
#define CHAR_CTRL_C         0x03    /* End of text (interrupt) */
#define CHAR_CTRL_D         0x04    /* End of transmission (EOF) */
#define CHAR_CTRL_Z         0x1A    /* Suspend */
#define CHAR_BACKSPACE      0x08    /* Backspace */
#define CHAR_DELETE         0x7F    /* Delete */
#define CHAR_CR             0x0D    /* Carriage return */
#define CHAR_LF             0x0A    /* Line feed */

/* Pending read request (a reader blocked waiting for input) */
typedef struct {
    uint32_t reader_tid;    /* TID of the blocked reader (0 = slot empty) */
    uint32_t msg_id;        /* msg_id to echo in the reply */
    uint32_t max_len;       /* Maximum bytes requested */
} tty_pending_read_t;

/* TTY state (one per TTY) */
typedef struct {
    uint32_t flags;                  /* TTY_FLAG_* */
    uint32_t owner_tid;              /* TID of owning process (shell) */
    
    /* Input buffering */
    char     input_buf[TTY_INPUT_BUF_SIZE];
    uint32_t input_head;             /* Write position */
    uint32_t input_tail;             /* Read position */
    uint32_t input_count;            /* Number of buffered chars */
    
    /* Line buffer (canonical mode) */
    char     line_buf[TTY_LINE_BUF_SIZE];
    uint32_t line_len;               /* Current line length */
    uint32_t line_ready;             /* Line complete (Enter pressed) */
    
    /* Console association */
    uint32_t console_id;             /* Associated console (0-11) */

    /* Pending blocked readers: filled when app sends MSG_APP_READ but
     * no line is ready yet; drained by tty_process_enter / tty_input_char. */
    tty_pending_read_t pending_readers[TTY_MAX_PENDING_READERS];
    uint32_t           pending_count;
} tty_state_t;

/* TTY service functions */
void tty_init(void);
void tty_main(void);

/* Internal TTY operations */
void tty_input_char(tty_state_t *tty, char ch);
void tty_output_char(tty_state_t *tty, char ch);
void tty_output_string(tty_state_t *tty, const char *str, uint32_t len);
void tty_process_backspace(tty_state_t *tty);
void tty_process_enter(tty_state_t *tty);
int  tty_read_line(tty_state_t *tty, char *buf, uint32_t max_len);
int  tty_read_raw(tty_state_t *tty, char *buf, uint32_t max_len);
/* Flush any pending blocked read requests now that a line is ready */
void tty_flush_pending_readers(tty_state_t *tty);

#endif /* TTY_H */
