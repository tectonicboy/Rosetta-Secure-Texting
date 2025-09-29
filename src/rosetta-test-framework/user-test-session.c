#include "../client/network-code/client-primary-functions.h"


/* Command-line arguments will determine: 
 *   - Name of save file to use.
 *   - Unique temporary test-session ID, to attach to AF_UNIX socket file name.
 *
 *
 * 
 *
 */
int main(int argc, char** argv){

    uint8_t ret = init_client_interprocess_comms();

    if(ret){
        printf("[ERR] RTF client spawner: init_ipc failed!\n\n");
        exit(1);
    }    
    exit(0);

}
