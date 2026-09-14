/* UART driver - 16550A (QEMU riscv-virt 0x10000000), IOMMU-free MMIO+IRQ device.
 * Only gets: MMIO Frame cap (UART regs), IRQ cap (RDA). No kernel access,
 * crash -> micro-reboot (re-init with same caps, FIFOs cleared).
 *
 * Core is plain C (host-testable): TX/RX software FIFOs (256B), LSR-gated
 * transmit, IIR-decoded IRQ drain. All work bounded: putc/getc O(1),
 * IRQ drain at most 32 bytes per call.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../../kernel/include/cheri.h"
#include "../../kernel/include/cap.h"

/* 16550A register offsets (DLAB=0) */
#define UART_RBR 0u /* RX (read) */
#define UART_THR 0u /* TX (write) */
#define UART_IER 1u
#define UART_IIR 2u
#define UART_FCR 2u /* (write) */
#define UART_LCR 3u
#define UART_LSR 5u

#define UART_LSR_RX_READY 0x01u
#define UART_LSR_TX_EMPTY 0x20u
#define UART_IER_RDA      0x01u
#define UART_IIR_NO_INT   0x01u
#define UART_IIR_ID_MASK  0x0eu
#define UART_FCR_ENABLE   0x01u
#define UART_FCR_CLEAR_RX 0x02u
#define UART_FCR_CLEAR_TX 0x04u
#define UART_LCR_DLAB     0x80u
#define UART_LCR_8N1      0x03u

#define UART_FIFO_BITS 8
#define UART_FIFO_SIZE (1u << UART_FIFO_BITS)
#define UART_MAX_DRAIN 32u
#define UART_VIRT_IRQ 10u

typedef struct {
    uintptr_t mmio_base;
    size_t mmio_len;
    uint32_t irq; /* expect UART_VIRT_IRQ on riscv-virt */
} uart_caps_t;

typedef struct {
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_drops;
    uint64_t rx_drops;
    uint64_t irqs;
    uint64_t overruns;
    uint16_t tx_used;
    uint16_t rx_used;
} uart_stats_t;

static uart_caps_t u_caps;
static volatile uint8_t *u_regs;
#if !defined(__riscv)
static uint8_t host_uart_regs[8] __attribute__((aligned(4096)));
#endif
static uint8_t u_txfifo[UART_FIFO_SIZE];
static uint8_t u_rxfifo[UART_FIFO_SIZE];
static uint16_t u_tx_head, u_tx_tail, u_tx_used;
static uint16_t u_rx_head, u_rx_tail, u_rx_used;
static uart_stats_t u_st;
static bool u_irq_enabled;

void uart_driver_poll(void); /* forward: getc polls before poll is defined */

static inline uint8_t u_rd(uint32_t off) {
    return *(volatile uint8_t *)(u_regs + off);
}

static inline void u_wr(uint32_t off, uint8_t v) {
    *(volatile uint8_t *)(u_regs + off) = v;
}

bool uart_driver_init(uart_caps_t c) {
    u_caps = c;
    if (c.mmio_len < 8u || c.mmio_base == 0) return false;
#ifdef __CHERI_PURE_CAPABILITY__
    __capability void *cap = (void *)c.mmio_base;
    if (!__builtin_cheri_tag_get(cap)) return false;
    if (__builtin_cheri_length_get(cap) < c.mmio_len) return false;
    u_regs = (__capability volatile uint8_t *)cap;
#else
    /* Hybrid/target range check: UART lives in the MMIO window. */
    if (c.mmio_base < 0x10000000u || c.mmio_base + c.mmio_len > 0x20000000u)
        return false;
#if defined(__riscv)
    u_regs = (volatile uint8_t *)c.mmio_base;
#else
    memset(host_uart_regs, 0, sizeof(host_uart_regs));
    host_uart_regs[UART_LSR] = UART_LSR_TX_EMPTY; /* TX always ready on host */
    u_regs = (volatile uint8_t *)host_uart_regs;
#endif
#endif
    memset(u_txfifo, 0, sizeof(u_txfifo));
    memset(u_rxfifo, 0, sizeof(u_rxfifo));
    u_tx_head = u_tx_tail = u_tx_used = 0;
    u_rx_head = u_rx_tail = u_rx_used = 0;
    memset(&u_st, 0, sizeof(u_st));
    u_irq_enabled = false;
#ifdef __riscv
    /* Production init sequence: 8N1, divisor latch (QEMU ignores the baud
     * but real silicon needs it), FIFOs on + cleared, RDA IRQ armed. */
    u_wr(UART_LCR, UART_LCR_DLAB);
    u_wr(0u, 0x01u); /* DLL: 115200 @ 1.8432MHz reference */
    u_wr(1u, 0x00u); /* DLM */
    u_wr(UART_LCR, UART_LCR_8N1);
    u_wr(UART_FCR, (uint8_t)(UART_FCR_ENABLE | UART_FCR_CLEAR_RX | UART_FCR_CLEAR_TX));
    u_wr(UART_IER, UART_IER_RDA);
    u_irq_enabled = true;
#endif
    return true;
}

/* Non-blocking transmit: 0 on success, -1 when the TX FIFO is full. */
int uart_driver_putc(char c) {
    if (!u_regs) return -1;
    if (u_tx_used >= UART_FIFO_SIZE) { u_st.tx_drops++; return -1; }
    u_txfifo[u_tx_head] = (uint8_t)c;
    u_tx_head = (uint16_t)((u_tx_head + 1u) & (UART_FIFO_SIZE - 1u));
    u_tx_used++;
    u_st.tx_used = u_tx_used;
    /* Push down to the THR while the holding register is empty (bounded:
     * at most one byte per call keeps putc O(1) and WCET-flat). */
    if ((u_rd(UART_LSR) & UART_LSR_TX_EMPTY) && u_tx_used > 0) {
        u_wr(UART_THR, u_txfifo[u_tx_tail]);
        u_tx_tail = (uint16_t)((u_tx_tail + 1u) & (UART_FIFO_SIZE - 1u));
        u_tx_used--;
        u_st.tx_bytes++;
        u_st.tx_used = u_tx_used;
    }
    return 0;
}

/* Pump the TX FIFO to the device (bounded: 32 bytes per call). */
uint16_t uart_driver_tx_pump(void) {
    uint16_t n = 0;
    if (!u_regs) return 0;
    while (u_tx_used > 0 && n < UART_MAX_DRAIN) {
        if (!(u_rd(UART_LSR) & UART_LSR_TX_EMPTY)) break;
        u_wr(UART_THR, u_txfifo[u_tx_tail]);
        u_tx_tail = (uint16_t)((u_tx_tail + 1u) & (UART_FIFO_SIZE - 1u));
        u_tx_used--;
        u_st.tx_bytes++;
        n++;
    }
    u_st.tx_used = u_tx_used;
    return n;
}

/* Non-blocking receive: byte 0-255, or -1 when empty. */
int uart_driver_getc(void) {
    if (!u_regs) return -1;
    uart_driver_poll();
    if (u_rx_used == 0) return -1;
    int c = u_rxfifo[u_rx_tail];
    u_rx_tail = (uint16_t)((u_rx_tail + 1u) & (UART_FIFO_SIZE - 1u));
    u_rx_used--;
    u_st.rx_used = u_rx_used;
    return c;
}

/* Test hook: inject one serial byte as if the device raised RDA. */
void uart_driver_sim_rx(uint8_t b) {
    if (u_rx_used >= UART_FIFO_SIZE) { u_st.rx_drops++; return; }
    u_rxfifo[u_rx_head] = b;
    u_rx_head = (uint16_t)((u_rx_head + 1u) & (UART_FIFO_SIZE - 1u));
    u_rx_used++;
    u_st.rx_bytes++;
    u_st.rx_used = u_rx_used;
}

/* Drain device RX + report IRQ (bounded: 32 bytes per call). */
void uart_driver_poll(void) {
    uint32_t n = 0;
    if (!u_regs) return;
    while (n < UART_MAX_DRAIN) {
        if (!(u_rd(UART_LSR) & UART_LSR_RX_READY)) break;
        uint8_t b = u_rd(UART_RBR);
        if (u_rx_used >= UART_FIFO_SIZE) {
            u_st.rx_drops++;
            u_st.overruns++;
        } else {
            u_rxfifo[u_rx_head] = b;
            u_rx_head = (uint16_t)((u_rx_head + 1u) & (UART_FIFO_SIZE - 1u));
            u_rx_used++;
            u_st.rx_bytes++;
        }
        n++;
    }
    u_st.rx_used = u_rx_used;
}

void uart_driver_handle_irq(void) {
    if (!u_regs) return;
    u_st.irqs++;
#ifdef __riscv
    /* IIR decode: keep draining while the device reports RX data. */
    for (uint32_t k = 0; k < UART_MAX_DRAIN; k++) {
        uint8_t iir = u_rd(UART_IIR);
        if (iir & UART_IIR_NO_INT) break;
        if ((iir & UART_IIR_ID_MASK) == 0x04u) uart_driver_poll();
        else break; /* THRE/modem: nothing queued in this driver */
    }
#else
    uart_driver_poll();
#endif
}

void uart_driver_stats(uart_stats_t *out) {
    if (!out) return;
    *out = u_st;
    out->tx_used = u_tx_used;
    out->rx_used = u_rx_used;
}

bool uart_driver_irq_armed(void) { return u_irq_enabled; }

void uart_driver_reboot(void) {
    /* Micro-reboot: FIFOs cleared, device re-init with same caps. */
    u_irq_enabled = false;
    uart_driver_init(u_caps);
}
