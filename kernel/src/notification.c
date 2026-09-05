#include "../include/notification.h"
#include <string.h>

kerror_t notification_init(notification_t *ntfn){
    if(!ntfn) return ERR_INVALID_ARG;
    memset(ntfn,0,sizeof(*ntfn));
    return ERR_OK;
}
kerror_t notification_signal(notification_t *ntfn, uint64_t badge){
    if(!ntfn || badge==0) return ERR_INVALID_ARG;
    // Coalesce badges - production: OR, not overwrite
    ntfn->badge |= badge;
    // If waiter exists, wake it (caller handles scheduling)
    return ERR_OK;
}
kerror_t notification_wait(notification_t *ntfn, uint32_t waiter, uint64_t *out_badge){
    if(!ntfn || !out_badge) return ERR_INVALID_ARG;
    if(ntfn->badge){
        *out_badge = ntfn->badge;
        ntfn->badge = 0;
        return ERR_OK;
    }
    ntfn->has_waiter = true;
    ntfn->waiter_tcb = waiter;
    return ERR_OK; // caller blocks TCB
}
kerror_t notification_poll(notification_t *ntfn, uint64_t *out_badge){
    if(!ntfn || !out_badge) return ERR_INVALID_ARG;
    *out_badge = ntfn->badge;
    ntfn->badge = 0;
    return ERR_OK;
}
kerror_t notification_bind(notification_t *ntfn, uint32_t tcb_id){
    if(!ntfn) return ERR_INVALID_ARG;
    ntfn->bound_tcb = tcb_id;
    return ERR_OK;
}
