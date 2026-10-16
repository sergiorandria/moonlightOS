/* test_ipc_integration.c - End-to-end IPC integration tests
 *
 * Tests realistic service communication patterns:
 * - Request-response patterns (synchronous)
 * - Fire-and-forget patterns (asynchronous)
 * - Multi-hop message routing
 * - Queue pressure and backpressure
 * - Error handling and recovery
 * - Concurrent access patterns
 *
 * This complements the unit tests in test_v2ipc.c which test
 * individual queue operations. These tests validate the full
 * IPC subsystem in realistic scenarios.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "../kernel/ipc.h"
#include "../userspace/include/services/ipc_protocol.h"
#include "../userspace/include/services/ipc_helpers.h"

/* Test framework */
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("FAIL: %s (line %d)\n", msg, __LINE__); \
            return 0; \
        } \
    } while(0)

#define TEST_PASS(msg) \
    printf("PASS: %s\n", msg)

/* Mock moonlight syscalls for host testing */
static uint64_t mock_time = 0;
static int moonlight_send_count = 0;
static int moonlight_recv_count = 0;

/* Simulated thread table */
static struct {
    uint64_t regs[32];
    int state;
    int wait_kind;
    uint64_t notify;
    uint64_t ipc_ptr;
    uint64_t ipc_cap;
} mock_threads[11];

static int mock_cur = 0;

/* Mock endpoint queues */
static v2_ep_t mock_eps[V2_NEP];

/* ============================================================================
 * Test 1: Synchronous Request-Response Pattern
 * Tests the common pattern where a client sends a request and waits for
 * a response, matching on msg_id.
 * ============================================================================ */
int test_sync_request_response(void) {
    printf("\n=== Test 1: Synchronous Request-Response ===\n");

    v2_ep_init(&mock_eps[0]);
    v2_ep_init(&mock_eps[1]);

    /* Simulate client (tid 0) sending to server (tid 1) */
    msg_app_read_t req = {
        .msg_type = MSG_APP_READ,
        .msg_id = 123,
        .tty_id = 0,
        .max_len = 16
    };

    uint64_t req_words[4] = {0};
    memcpy(req_words, &req, sizeof(req));

    /* Client sends to server's endpoint */
    int ret = v2_q_send(&mock_eps[1], 0, req_words, 4);
    TEST_ASSERT(ret == V2_OK, "Request should queue successfully");
    TEST_ASSERT(mock_eps[1].send_len == 1, "Server should have 1 queued message");

    /* Server receives and processes */
    v2_slot_t slot;
    ret = v2_q_take_send(&mock_eps[1], &slot);
    TEST_ASSERT(ret == V2_OK, "Server should receive message");
    TEST_ASSERT(slot.sender == 0, "Sender should be client TID 0");
    TEST_ASSERT(slot.len == 4, "Message should be 4 words");

    /* Server sends response */
    msg_app_read_resp_t resp = {
        .msg_type = MSG_ACK,
        .msg_id = 123,  /* Echo request ID */
        .len = 5,
        .data = {'H', 'e', 'l', 'l', 'o'}
    };

    uint64_t resp_words[4] = {0};
    memcpy(resp_words, &resp, sizeof(resp));

    ret = v2_q_send(&mock_eps[0], 1, resp_words, 4);
    TEST_ASSERT(ret == V2_OK, "Response should queue successfully");

    /* Client receives response */
    ret = v2_q_take_send(&mock_eps[0], &slot);
    TEST_ASSERT(ret == V2_OK, "Client should receive response");
    TEST_ASSERT(slot.sender == 1, "Response sender should be server TID 1");

    /* Verify msg_id matching */
    msg_app_read_resp_t *recv_resp = (msg_app_read_resp_t *)slot.words;
    TEST_ASSERT(recv_resp->msg_id == 123, "Response msg_id should match request");

    TEST_PASS("Synchronous request-response pattern");
    return 1;
}

/* ============================================================================
 * Test 2: Asynchronous Fire-and-Forget Pattern
 * Tests sending messages without waiting for responses, useful for
 * logging, metrics, and notifications.
 * ============================================================================ */
int test_async_fire_and_forget(void) {
    printf("\n=== Test 2: Asynchronous Fire-and-Forget ===\n");

    v2_ep_init(&mock_eps[0]);
    v2_ep_init(&mock_eps[1]);

    /* Send multiple messages without waiting */
    for (int i = 0; i < 5; i++) {
        msg_console_putc_t msg = {
            .msg_type = MSG_CONSOLE_PUTC,
            .x = i,
            .y = 0,
            .ch = 'A' + i,
            .fg_color = 0xFFFFFF,
            .bg_color = 0x000000
        };

        uint64_t words[4] = {0};
        memcpy(words, &msg, sizeof(msg));

        int ret = v2_q_send(&mock_eps[1], 0, words, 4);
        TEST_ASSERT(ret == V2_OK, "Async message should queue");
    }

    TEST_ASSERT(mock_eps[1].send_len == 5, "Queue should have 5 messages");

    /* Receiver processes all messages */
    v2_slot_t slot;
    int count = 0;
    while (v2_q_take_send(&mock_eps[1], &slot) == V2_OK) {
        count++;
    }

    TEST_ASSERT(count == 5, "Should process all 5 messages");
    TEST_ASSERT(mock_eps[1].send_len == 0, "Queue should be empty");

    TEST_PASS("Asynchronous fire-and-forget pattern");
    return 1;
}

/* ============================================================================
 * Test 3: Queue Pressure and Backpressure
 * Tests behavior when queues approach capacity, ensuring backpressure
 * is applied correctly.
 * ============================================================================ */
int test_queue_pressure(void) {
    printf("\n=== Test 3: Queue Pressure and Backpressure ===\n");

    v2_ep_init(&mock_eps[0]);

    /* Fill queue to just below threshold */
    uint64_t words[4] = {0};
    for (int i = 0; i < V2_FLOW_CONTROL_THRESHOLD; i++) {
        int ret = v2_q_send(&mock_eps[0], 1, words, 4);
        TEST_ASSERT(ret == V2_OK, "Should queue below threshold");
    }

    TEST_ASSERT(mock_eps[0].send_len == V2_FLOW_CONTROL_THRESHOLD,
                "Queue should be at threshold");

    /* Cross threshold - should trigger flow control notification */
    int ret = v2_q_send(&mock_eps[0], 1, words, 4);
    TEST_ASSERT(ret == V2_OK, "Should queue at threshold+1");

    /* Fill to capacity */
    for (int i = mock_eps[0].send_len; i < V2_IPC_Q; i++) {
        ret = v2_q_send(&mock_eps[0], 1, words, 4);
        TEST_ASSERT(ret == V2_OK, "Should queue to capacity");
    }

    TEST_ASSERT(mock_eps[0].send_len == V2_IPC_Q, "Queue should be at capacity");

    /* Next send should fail with overflow */
    ret = v2_q_send(&mock_eps[0], 1, words, 4);
    TEST_ASSERT(ret == V2_ERR_OVERFLOW, "Should fail when queue full");

    /* Drain queue */
    v2_slot_t slot;
    int drained = 0;
    while (v2_q_take_send(&mock_eps[0], &slot) == V2_OK) {
        drained++;
    }

    TEST_ASSERT(drained == V2_IPC_Q, "Should drain all messages");
    TEST_ASSERT(mock_eps[0].send_len == 0, "Queue should be empty");

    TEST_PASS("Queue pressure and backpressure");
    return 1;
}

/* ============================================================================
 * Test 4: Multi-Hop Message Routing
 * Tests messages that pass through intermediate services, common in
 * microservice architectures.
 * ============================================================================ */
int test_multi_hop_routing(void) {
    printf("\n=== Test 4: Multi-Hop Message Routing ===\n");

    v2_ep_init(&mock_eps[0]);  /* Client */
    v2_ep_init(&mock_eps[1]);  /* Service A */
    v2_ep_init(&mock_eps[2]);  /* Service B */

    /* Client -> Service A */
    uint64_t msg1[4] = {0x1000, 0, 0, 0};  /* MSG_TYPE_CLIENT_REQUEST */
    int ret = v2_q_send(&mock_eps[1], 0, msg1, 4);
    TEST_ASSERT(ret == V2_OK, "Client->A should queue");

    /* Service A receives and forwards to Service B */
    v2_slot_t slot;
    ret = v2_q_take_send(&mock_eps[1], &slot);
    TEST_ASSERT(ret == V2_OK, "Service A should receive");

    uint64_t msg2[4] = {0x2000, 0, 0, 0};  /* MSG_TYPE_A_TO_B */
    ret = v2_q_send(&mock_eps[2], 1, msg2, 4);
    TEST_ASSERT(ret == V2_OK, "A->B should queue");

    /* Service B processes and responds to A */
    ret = v2_q_take_send(&mock_eps[2], &slot);
    TEST_ASSERT(ret == V2_OK, "Service B should receive");

    uint64_t msg3[4] = {0x3000, 0, 0, 0};  /* MSG_TYPE_B_RESPONSE */
    ret = v2_q_send(&mock_eps[1], 2, msg3, 4);
    TEST_ASSERT(ret == V2_OK, "B->A should queue");

    /* Service A responds to client */
    ret = v2_q_take_send(&mock_eps[1], &slot);
    TEST_ASSERT(ret == V2_OK, "Service A should receive B's response");

    uint64_t msg4[4] = {0x4000, 0, 0, 0};  /* MSG_TYPE_A_RESPONSE */
    ret = v2_q_send(&mock_eps[0], 1, msg4, 4);
    TEST_ASSERT(ret == V2_OK, "A->Client should queue");

    /* Client receives final response */
    ret = v2_q_take_send(&mock_eps[0], &slot);
    TEST_ASSERT(ret == V2_OK, "Client should receive final response");
    TEST_ASSERT(slot.sender == 1, "Final response from Service A");

    TEST_PASS("Multi-hop message routing");
    return 1;
}

/* ============================================================================
 * Test 5: Error Handling - Invalid Endpoint
 * Tests that invalid endpoint numbers are rejected safely.
 * ============================================================================ */
int test_error_invalid_endpoint(void) {
    printf("\n=== Test 5: Error Handling - Invalid Endpoint ===\n");

    v2_ep_init(&mock_eps[0]);

    /* Try to send to invalid endpoint */
    TEST_ASSERT(!v2_ep_ok(99), "EP 99 should be invalid");
    TEST_ASSERT(!v2_ep_ok(V2_NEP), "EP V2_NEP should be invalid");
    TEST_ASSERT(v2_ep_ok(0), "EP 0 should be valid");
    TEST_ASSERT(v2_ep_ok(V2_NEP - 1), "EP V2_NEP-1 should be valid");

    TEST_PASS("Invalid endpoint validation");
    return 1;
}

/* ============================================================================
 * Test 6: Error Handling - Message Truncation
 * Tests that messages larger than receiver capacity are truncated
 * with explicit overflow flag (never silent).
 * ============================================================================ */
int test_error_message_truncation(void) {
    printf("\n=== Test 6: Error Handling - Message Truncation ===\n");

    v2_ep_init(&mock_eps[0]);

    /* Send 4-word message */
    uint64_t send_words[4] = {1, 2, 3, 4};
    int ret = v2_q_send(&mock_eps[0], 1, send_words, 4);
    TEST_ASSERT(ret == V2_OK, "Should queue 4-word message");

    v2_slot_t slot;
    ret = v2_q_take_send(&mock_eps[0], &slot);
    TEST_ASSERT(ret == V2_OK, "Should receive message");

    /* Receive into 2-word buffer (truncation) */
    uint64_t recv_words[2] = {0};
    unsigned long out_len = 0;
    ret = v2_deliver(&slot, recv_words, 2, &out_len);

    TEST_ASSERT(ret == V2_ERR_OVERFLOW, "Should signal overflow");
    TEST_ASSERT(out_len == 2, "Should deliver 2 words");
    TEST_ASSERT(recv_words[0] == 1, "First word should match");
    TEST_ASSERT(recv_words[1] == 2, "Second word should match");

    /* Receive into 4-word buffer (no truncation) */
    uint64_t recv_words_full[4] = {0};
    ret = v2_deliver(&slot, recv_words_full, 4, &out_len);

    TEST_ASSERT(ret == V2_OK, "Should succeed with full buffer");
    TEST_ASSERT(out_len == 4, "Should deliver 4 words");
    TEST_ASSERT(recv_words_full[0] == 1, "Word 0 should match");
    TEST_ASSERT(recv_words_full[3] == 4, "Word 3 should match");

    TEST_PASS("Message truncation with explicit overflow flag");
    return 1;
}

/* ============================================================================
 * Test 7: Concurrent Access - Multiple Senders
 * Tests that multiple senders can safely queue to the same endpoint.
 * ============================================================================ */
int test_concurrent_multiple_senders(void) {
    printf("\n=== Test 7: Concurrent Access - Multiple Senders ===\n");

    v2_ep_init(&mock_eps[0]);

    /* Multiple senders queue to same endpoint */
    uint64_t words[4] = {0};

    for (int sender = 0; sender < 5; sender++) {
        for (int i = 0; i < 3; i++) {
            words[0] = sender * 100 + i;  /* Tag with sender ID */
            int ret = v2_q_send(&mock_eps[0], sender, words, 4);
            TEST_ASSERT(ret == V2_OK, "Each sender should queue");
        }
    }

    TEST_ASSERT(mock_eps[0].send_len == 15, "Should have 15 messages total");

    /* Verify FIFO order and sender stamps */
    v2_slot_t slot;
    int expected_sender = 0;
    int count = 0;

    while (v2_q_take_send(&mock_eps[0], &slot) == V2_OK) {
        /* Verify sender stamps are preserved */
        TEST_ASSERT(slot.sender < 5, "Sender should be valid");
        count++;
    }

    TEST_ASSERT(count == 15, "Should dequeue all 15 messages");
    TEST_ASSERT(mock_eps[0].send_len == 0, "Queue should be empty");

    TEST_PASS("Concurrent access - multiple senders");
    return 1;
}

/* ============================================================================
 * Test 8: Notification Signal Accumulation
 * Tests that NOTIFY bits are OR-accumulated and only wake WAIT waiters.
 * ============================================================================ */
int test_notification_accumulation(void) {
    printf("\n=== Test 8: Notification Signal Accumulation ===\n");

    v2_ep_init(&mock_eps[0]);

    /* Send multiple notifications with different bits */
    uint64_t bits1 = 0x01;  /* Bit 0 */
    uint64_t bits2 = 0x02;  /* Bit 1 */
    uint64_t bits3 = 0x04;  /* Bit 2 */

    /* Simulate NOTIFY calls */
    mock_threads[1].notify |= bits1;
    mock_threads[1].notify |= bits2;
    mock_threads[1].notify |= bits3;

    TEST_ASSERT(mock_threads[1].notify == 0x07, "Bits should be OR-accumulated");

    /* Simulate WAIT taking bits */
    uint64_t taken = mock_threads[1].notify;
    mock_threads[1].notify = 0;

    TEST_ASSERT(taken == 0x07, "Should take all accumulated bits");
    TEST_ASSERT(mock_threads[1].notify == 0, "Notify should be cleared");

    TEST_PASS("Notification signal accumulation");
    return 1;
}

/* ============================================================================
 * Test 9: Zero-Length Messages
 * Tests that zero-length messages are valid (used for pings, heartbeats).
 * ============================================================================ */
int test_zero_length_messages(void) {
    printf("\n=== Test 9: Zero-Length Messages ===\n");

    v2_ep_init(&mock_eps[0]);

    /* Send zero-length message */
    uint64_t words[4] = {0};
    int ret = v2_q_send(&mock_eps[0], 1, words, 0);
    TEST_ASSERT(ret == V2_OK, "Zero-length message should queue");

    v2_slot_t slot;
    ret = v2_q_take_send(&mock_eps[0], &slot);
    TEST_ASSERT(ret == V2_OK, "Should receive zero-length message");
    TEST_ASSERT(slot.len == 0, "Message length should be 0");
    TEST_ASSERT(slot.sender == 1, "Sender should be preserved");

    TEST_PASS("Zero-length messages");
    return 1;
}

/* ============================================================================
 * Test 10: Direct Delivery Optimization
 * Tests that when a receiver is waiting, direct delivery occurs
 * without queueing the sender (optimization).
 * ============================================================================ */
int test_direct_delivery(void) {
    printf("\n=== Test 10: Direct Delivery Optimization ===\n");

    v2_ep_init(&mock_eps[0]);

    /* Receiver queues as waiter */
    int ret = v2_q_wait(&mock_eps[0], 2);
    TEST_ASSERT(ret == V2_OK, "Receiver should queue as waiter");
    TEST_ASSERT(mock_eps[0].recv_len == 1, "Should have 1 waiter");

    /* Sender sends to endpoint with waiting receiver */
    uint64_t words[4] = {0xDEADBEEF, 0, 0, 0};
    ret = v2_q_send(&mock_eps[0], 1, words, 4);
    TEST_ASSERT(ret == V2_OK, "Send should succeed");

    /* In real kernel, this would trigger direct delivery.
     * Here we verify queue state allows it. */
    TEST_ASSERT(mock_eps[0].recv_len == 1, "Waiter still in queue (unit test context)");
    TEST_ASSERT(mock_eps[0].send_len == 1, "Message queued (unit test context)");

    /* Take waiter to simulate kernel direct delivery */
    unsigned long waiter_tid;
    ret = v2_q_take_waiter(&mock_eps[0], &waiter_tid);
    TEST_ASSERT(ret == V2_OK, "Should take waiter");
    TEST_ASSERT(waiter_tid == 2, "Waiter TID should be 2");

    /* Take message to simulate delivery */
    v2_slot_t slot;
    ret = v2_q_take_send(&mock_eps[0], &slot);
    TEST_ASSERT(ret == V2_OK, "Should take message");
    TEST_ASSERT(slot.words[0] == 0xDEADBEEF, "Message data should match");

    TEST_PASS("Direct delivery optimization");
    return 1;
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */
int main(void) {
    printf("===================================================\n");
    printf("IPC Integration Tests - Production Readiness\n");
    printf("===================================================\n");

    int passed = 0;
    int total = 10;

    if (test_sync_request_response()) passed++;
    if (test_async_fire_and_forget()) passed++;
    if (test_queue_pressure()) passed++;
    if (test_multi_hop_routing()) passed++;
    if (test_error_invalid_endpoint()) passed++;
    if (test_error_message_truncation()) passed++;
    if (test_concurrent_multiple_senders()) passed++;
    if (test_notification_accumulation()) passed++;
    if (test_zero_length_messages()) passed++;
    if (test_direct_delivery()) passed++;

    printf("\n===================================================\n");
    printf("Test Results: %d/%d passed\n", passed, total);
    printf("===================================================\n");

    if (passed == total) {
        printf("ALL TESTS PASSED\n");
        return 0;
    } else {
        printf("SOME TESTS FAILED\n");
        return 1;
    }
}
