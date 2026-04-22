#include "../lib/rosetta-helpers.h"
#include "../lib/bigint.h"
#include "../lib/cryptolib.h"

/* These function pointers tell the server whether to communicate through
 * Unix Domain sockets, or through Internet sockets. If the server was started
 * for the Rosetta Testing Framework, communication with test clients, which are
 * local OS processes talking to each other, simulating real people texting,
 * is done via locak unix interprocess communications (AF_UNIX sockets). If the
 * server is to be run normally for real Rosetta users to tune in to chatrooms
 * and text each other, Internet sockets provide the communication mechanism.
 *
 * The two communication mechanisms need different code for (1) initialization,
 * (2) transmitting a message to a known client, (3) receiving a message sent by
 * a known client and (4) accepting a newly arrived user/test messaging client.
 *
 * A command-line argument determines whether the server was started for the
 * testing framework or for the real system, and this in turn sets these
 * function pointers to the actual respective functions that implement the 4
 * differing communication operations. This is at server initialization time.
 *
 * This allows for an elegant way to simplify in-server communication code while
 * maintaining working messaging both for the Rosetta Test Framework and for the
 * real Rosetta system with only one set of simple, descriptive API functions,
 * instead of polluting server code with AF_UNIX / INET socket-specific code.
 *
 * Now, server packet and primary functions can call the generic communication
 * interface functions via these function pointers, relying on the fact that
 * they will have been set to the correct concrete communication functions.
 */
uint8_t(*init_communication)(void);
uint8_t(*transmit_payload)  (uint64_t socket_ix, uint8_t* buf, size_t send_siz);
ssize_t(*receive_payload)   (uint64_t socket_ix, uint8_t* buf, size_t max_siz);
uint8_t(*onboard_new_client)(uint64_t socket_ix);

#include "server-communications.h"
#include "server-packet-functions.h"
#include "server-primary-functions.h"

int main(int argc, char* argv[])
{
    u8  ret = 0;
    u32 status = 0;
    u64 curr_free_socket_ix;
    uint8_t thread_func_arg_buf[sizeof(curr_free_socket_ix)];
    int arg1;

    /* Function pointer set to respective socket initialization routine. */

    if(argc != 2){
        printf("[ERR] Server: Needs 1 cmd line arg: 0 = regular, 1 = RTF.\n");
        exit(1);
    }

    arg1 = atoi(argv[1]);

    /* Set 4 function pointers for the communication mechanism (socket type)  */

    /* If server started for Rosetta Test Framework, use AF_UNIX sockets. */
    if(arg1 == 1){
        init_communication = ipc_init_communication;
        transmit_payload   = ipc_transmit_payload;
        receive_payload    = ipc_receive_payload;
        onboard_new_client = ipc_onboard_new_client;
    }
    /* If server started for normal Rosetta texting, use Internet sockets. */
    else if(arg1 == 0){
        init_communication = tcp_init_communication;
        transmit_payload   = tcp_transmit_payload;
        receive_payload    = tcp_receive_payload;
        onboard_new_client = tcp_onboard_new_client;
    }
    else{
        printf("[ERR] Server: must pass 0 for Rosetta, 1 for Test Framework.\n");
        exit(1);
    }

    /**************************************************************************/

    /* Initialize Linux Sockets API stuff, load cryptographic artifacts. */
    status = self_init();

    if(status){
        printf("\n[ERR] Server: Could not complete self initialization!\n\n");
        exit(1);
    }
    printf("\n\n[OK]  Server: SUCCESS - Finished self initializing!\n\n");

    while(1){
        curr_free_socket_ix = next_free_user_ix;

        /* Find the next free socket index. */
        ++next_free_user_ix;

        while(next_free_user_ix < MAX_CLIENTS){
            if(!(users_status_bitmask & (1ULL<<(63ULL - next_free_user_ix)))){
                break;
            }
            ++next_free_user_ix;
        }

        /**********************************************************************/

        /* Block here until a newly seen client wants to log in to Rosetta. */

        ret = onboard_new_client(curr_free_socket_ix);
        login_not_finished = 1;

        if(ret){
            printf("[ERR] Server: accepting a newly seen client failed!\n");
            login_not_finished = 0;
            next_free_user_ix = curr_free_socket_ix;
            continue;
        }

        /**********************************************************************/

        memcpy( thread_func_arg_buf
               ,&curr_free_socket_ix
               ,sizeof(curr_free_socket_ix)
              );

        pthread_mutex_lock(&mutex);

        /* Give this new client a thread on which their socket will be stuck
         * on a recv() call loop and send() whatever the msg processor needs to.
         */

        /* Start the recv() looping thread for this new client. */
        pthread_create(
            &(client_thread_ids[curr_free_socket_ix])
           ,NULL
           , start_new_client_thread
           ,(void*)thread_func_arg_buf
        );

        pthread_detach(client_thread_ids[curr_free_socket_ix]);
        pthread_mutex_unlock(&mutex);
    }

    return 0;
}
