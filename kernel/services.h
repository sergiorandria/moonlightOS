/* kernel/services.h - Boot thread / endpoint / qube catalog.
 *
 * Mechanism names only. Policy, drivers, and protocol live in userspace.
 * NTHREADS == V2_CAP_THREADS == 11: the table is full. Reserved future
 * servers (USB, audio, 9p, extra NIC) MUST NOT grow this file's live
 * tids; they wait on a bump + proof replay and spawn as U-mode ELFs.
 */
#ifndef V2_SERVICES_H
#define V2_SERVICES_H

#include "caps.h"
#include "ipc.h"
#include "qube.h"

#define T_DEMO_A 0
#define T_DEMO_B 1
#define T_MEM 2
#define T_QREXEC 3
#define T_ADMIN 4
#define T_FIREWALL 5
#define T_NET 6
#define T_CAP_SCRATCH 7
#define T_VAULT 8
#define T_CRYPTBLK 9
#define T_GUI 10

#define EP_OF_TID(t) (t) /* EP i owned by tid i */

#define QUBE_DEMO 0
#define QUBE_MEM 1
#define QUBE_QREXEC 2
#define QUBE_ADMIN 3
#define QUBE_FW 4
#define QUBE_NET 5
#define QUBE_VAULT 6
#define QUBE_CRYPT 7
#define QUBE_GUI 8

/* Future userspace qubes (not allocated). Named so stubs compile against
 * one catalog; values are invalid labels until V2_QUBES_MAX grows. */
#define QUBE_USB_RESERVED 9
#define QUBE_AUDIO_RESERVED 10
#define QUBE_FS9P_RESERVED 11

_Static_assert(T_GUI + 1 == V2_CAP_THREADS, "live catalog must match cap threads");
_Static_assert(T_GUI + 1 == V2_NEP, "live catalog must match endpoints");
_Static_assert(QUBE_GUI + 1 == V2_QUBES_MAX, "live catalog must match qube labels");

#endif /* V2_SERVICES_H */
