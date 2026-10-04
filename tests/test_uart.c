#include "../userspace/abi/cap.h"
#include "../userspace/abi/cheri.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../userspace/drivers/uart.c"

int main(void) {
    printf("=== uart driver tests ===\n");

    /* init validation */
    uart_caps_t bad = {0};
    assert(uart_driver_init(bad) == false);
    bad.mmio_base = 0x10000000u; bad.mmio_len = 4;
    assert(uart_driver_init(bad) == false);
    bad.mmio_base = 0x00001000u; bad.mmio_len = 8;
    assert(uart_driver_init(bad) == false);
    printf("PASS: rejects bad caps\n");

    uart_caps_t good = {0};
    good.mmio_base = 0x10000000u; good.mmio_len = 0x1000; good.irq = 10;
    assert(uart_driver_init(good) == true);
    printf("PASS: init OK\n");

    /* TX path: putc queues, pump drains while THR empty */
    assert(uart_driver_putc('H') == 0);
    assert(uart_driver_putc('i') == 0);
    uart_stats_t st = {0};
    uart_driver_stats(&st);
    /* Host LSR reports TX empty: each putc pushed straight through */
    assert(st.tx_bytes == 2 && st.tx_used == 0);
    printf("PASS: putc transmits when THR empty\n");

    /* RX path via sim hook + getc */
    uart_driver_sim_rx('A');
    uart_driver_sim_rx('B');
    assert(uart_driver_getc() == 'A');
    assert(uart_driver_getc() == 'B');
    assert(uart_driver_getc() == -1);
    printf("PASS: sim RX + getc order\n");

    /* TX FIFO full: 256 queued max (force by busy THR) */
    host_uart_regs[UART_LSR] = 0x00; /* THR busy: nothing drains */
    int n = 0;
    for (int i = 0; i < 300; i++)
        if (uart_driver_putc((char)('a' + (i % 26))) == 0) n++;
    assert(n == 256);
    assert(uart_driver_putc('z') == -1); /* full */
    uart_driver_stats(&st);
    assert(st.tx_used == 256 && st.tx_drops == (300 - 256 + 1));
    host_uart_regs[UART_LSR] = UART_LSR_TX_EMPTY;
    uint16_t pumped = uart_driver_tx_pump();
    assert(pumped == 32); /* bounded */
    uart_driver_stats(&st);
    assert(st.tx_used == 256 - 32);
    printf("PASS: TX full rejected, pump bounded 32/call\n");

    /* RX overrun: fill via sim, extra drops counted */
    uart_driver_init(good); /* reset */
    for (int i = 0; i < 256; i++) uart_driver_sim_rx((uint8_t)i);
    uart_driver_sim_rx(0xFF);
    uart_driver_stats(&st);
    assert(st.rx_used == 256 && st.rx_drops == 1);
    printf("PASS: RX overrun counted\n");

    /* poll drains device RBR while LSR reports ready (bounded) */
    uart_driver_init(good);
    host_uart_regs[UART_LSR] = (uint8_t)(UART_LSR_TX_EMPTY | UART_LSR_RX_READY);
    host_uart_regs[UART_RBR] = 'Q';
    uart_driver_poll();
    assert(uart_driver_getc() == 'Q');
    printf("PASS: poll drains device RBR\n");

    /* IRQ path counts */
    uart_driver_handle_irq();
    uart_driver_stats(&st);
    assert(st.irqs == 1);
    printf("PASS: handle_irq counted\n");

    /* reboot clears everything */
    uart_driver_putc('x');
    uart_driver_reboot();
    uart_driver_stats(&st);
    assert(st.tx_bytes == 0 && st.rx_bytes == 0 && st.irqs == 0);
    assert(st.tx_used == 0 && st.rx_used == 0);
    printf("PASS: reboot clears FIFOs + stats\n");

    /* A failed reinit drops both the old mapping and its reboot snapshot. */
    assert(uart_driver_init(bad) == false);
    assert(uart_driver_putc('x') == -1);
    uart_driver_reboot();
    assert(uart_driver_putc('x') == -1);
    printf("PASS: failed reinit leaves driver unbound\n");

    printf("ALL UART TESTS PASS\n");
    return 0;
}
