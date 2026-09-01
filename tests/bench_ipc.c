#include "../kernel/include/endpoint.h"
#include <time.h>
#include <stdio.h>
int main(void){
    endpoint_t ep={0};
    ipc_msg_t m={0}; m.length=4;
    clock_t s=clock();
    for(int i=0;i<1000000;i++){ endpoint_send(&ep,0,&m); ipc_msg_t o; endpoint_recv(&ep,1,&o); }
    clock_t e=clock();
    double us = (double)(e-s)/CLOCKS_PER_SEC*1e6;
    printf("1M IPC round-trips: %.0f us, %.1f ns/msg\n", us, us/1e6*1000);
    return 0;
}
