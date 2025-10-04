#include "../client/network-code/client-primary-functions.h"


/* Command-line arguments will determine: 
 *   - Name of save file to use.
 *   - Unique temporary test-session ID, to attach to AF_UNIX socket file name.
 *
 *
 * 
 *
 */
int main(void){

    init_communication = ipc_init_communication;
    transmit_payload   = ipc_transmit_payload;
    receive_payload    = ipc_receive_payload;

    /* Take save file name and password from stdin. */

    unsigned char  savefilename[16] = {'\0'};
    unsigned char* full_save_dir = NULL;
    uint8_t        status = 0;
    uint8_t        pw_buf[16] = {0};
    const char*    savedir = "./test-accounts/";

    printf("Pick a save file name for login: ");
    scanf("%15s", savefilename);

    full_save_dir =
          calloc(1, strlen(savedir) + strlen((const char*)savefilename));

    memcpy(full_save_dir, savedir, strlen(savedir));
    memcpy( full_save_dir + strlen(savedir)
           ,savefilename
           ,strlen((const char*)savefilename)
          );


    printf("Enter a password up to 15 characters: ");

    /* Read a string of UP TO 15 characters. No more. */
    scanf("%15s", (char*)pw_buf);

    status = login(pw_buf, strlen((char*)pw_buf), (char*)full_save_dir);

    if(status){
        printf("\n[ERR] RTF user spawner: login() failed.\n\n");
        goto label_cleanup;
    }


    goto label_success;

label_cleanup:

    free(full_save_dir);

label_success:

    return 0;
}
