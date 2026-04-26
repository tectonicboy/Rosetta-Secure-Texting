#include "../../src/client/network-code/client-primary-functions.h"
int main(){
    init_communication = ipc_init_communication;
    transmit_payload   = ipc_transmit_payload;
    receive_payload    = ipc_receive_payload;
    end_communication  = ipc_end_communication;
    uint8_t status;
    char*   savedir       = USER_SAVEFILES_DIR;
    char*   savefile      = "kevin";
    char    pwd[PASSWORD_BUF_SIZ];
		char    room_name[SMALL_FIELD_LEN]     = "ROOM1";
    char    password[2 * SMALL_FIELD_LEN]  = "150499";
    char    username[SMALL_FIELD_LEN]      = "Kev";
		size_t  username_len  = 3;
		size_t  room_name_len = 5;
    size_t  pwd_len       = 6;
    char    full_save_dir[1024];
    memset(full_save_dir, 0x00, 1024);
    strncpy(full_save_dir, savedir, strlen(savedir));
    strncpy(full_save_dir + strlen(savedir), savefile, strlen(savefile));
		strncpy(pwd, password, pwd_len);
		printf("[OK]  RTF Simulation 1: Kev is calling login() now.\n");
    status = login((unsigned char*)pwd, pwd_len, full_save_dir);
    if(status){
        printf("[ERR] RTF Simulation 1: Kev could not login.\n");
				exit(1);
    }
		else{
        printf("[OK]  RTF Simulation 1: Kev logged in!\n");
		}
    status = make_new_chatroom((unsigned char*)room_name, room_name_len,
                               (unsigned char*)username,  username_len);
		if(status){
				printf("[ERR] RTF Simulation 1: Kev could not make a chat room.\n");
				if(status == 2){
						printf("[ERR] RTF Simulation 1: Server reply to Kev's MAKE_ROOM \n"
									 "                        request took too long.\n");
				}
				exit(1);
		}
		else{
				printf("[OK]  RTF Simulation 1: Kev created a new chat room!\n");
		}
    sleep(10);
		/* send texts too, then close the chat room, wait (2) and exit rosetta */
    /* Send messages */
    const char* msgs[] = {"Hi from kev\0", "kev_msg_2a\0", "kev_msg_3b\0"};
    for(size_t i = 0; i < 3; ++i){
        send_text((unsigned char*)(msgs[i]), (uint64_t)(strlen(msgs[i])));
        printf("{OWN_INDEX: %lu} Displaying own msg: %s\n", own_ix, msgs[i]);
        sleep(1);
    }
		sleep(20);
    return 0;
}
