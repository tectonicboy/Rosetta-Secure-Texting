#include "../../src/client/network-code/client-primary-functions.h"
int main(){
    init_communication = ipc_init_communication;
    transmit_payload   = ipc_transmit_payload;
    receive_payload    = ipc_receive_payload;
    end_communication  = ipc_end_communication;
    uint8_t status;
    char*   savedir  = USER_SAVEFILES_DIR;
    char*   savefile = "devin";
    char    pwd[PASSWORD_BUF_SIZ];
    char    room_name[SMALL_FIELD_LEN]    = "ROOM1";
    char    password[2 * SMALL_FIELD_LEN] = "150499";
    char    username[SMALL_FIELD_LEN]     = "Devi";
    size_t  username_len  = 4;
    size_t  room_name_len = 5;
    size_t  pwd_len       = 6;
    char    full_save_dir[1024];
    memset(full_save_dir, 0x00, 1024);
    strncpy(full_save_dir, savedir, strlen(savedir));
    strncpy(full_save_dir + strlen(savedir), savefile, strlen(savefile));
    strncpy(pwd, password, pwd_len);
    printf("[OK]  RTF Simulation 1: Devi is calling login() now.\n");
    status = login((unsigned char*)pwd, pwd_len, full_save_dir);
    if(status){
        printf("[ERR] RTF Simulation 1: Devi could not login.\n");
        exit(1);
    }
    else{
        printf("[OK]  RTF Simulation 1: Devi logged in!\n");
    }
    status = join_chatroom((unsigned char*)room_name, room_name_len,
                           (unsigned char*)username,  username_len);
    if(status){
        printf("[ERR] RTF Simulation 1: Devi could not join a chat room.\n");
        if(status == 2){
            printf("[ERR] RTF Simulation 1: Server reply to Devi's JOIN_ROOM\n"
                   "                        request took too long.\n");
        }
        exit(1);
    }
    else{
        printf("[OK]  RTF Simulation 1: Devi join a chat room!\n");
    }
    sleep(2);
		/* Send messages */
    const char* msgs[] = {"Hi from devi\0", "devi_msg_2a\0", "devi_msg_3b\0"};
    for(size_t i = 0; i < 3; ++i){
        send_text((unsigned char*)(msgs[i]), (uint64_t)(strlen(msgs[i])));
				printf("{OWN_INDEX: %lu} Displaying own msg: %s\n", own_ix, msgs[i]);
        sleep(1);
    }
    sleep(2);
    return 0;
}
