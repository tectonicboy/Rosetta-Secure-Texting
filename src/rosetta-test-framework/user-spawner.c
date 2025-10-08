#include "../client/network-code/client-primary-functions.h"

void user_loop(void){

    int           user_option;
    char          input_user_option[1];
    unsigned char input_room_name[8];
    unsigned char input_user_name[8];
    unsigned char message[128];
    int           room_name_len;
    int           user_name_len;
    uint8_t       status;

    /* Beginning - login has just succeeded. At this point:
     *
     *  - Make a chatroom.
     *  - Join a chatroom.
     *  - Logout.
     */

label_begin_user:

    printf("\nNow you can select one of 3 test user options:\n");
    printf("1  --  Make a chatroom.");
    printf("2  --  Join a chatroom.");
    printf("3  --  Logout.");
    printf("\nPlease enter an option number: ");

label_try_again1:

    scanf("%1s", input_user_option);
    user_option = atoi(input_user_option);

    if( ! ((1 <= user_option) && (user_option <= 3)) ){
        printf("Option number entered must be 1, 2 or 3. Try again: \n");
        goto label_try_again1;
    }
    if(user_option == 1){
        printf("Pick a room name and user name, up to 7 characters each.\n");
   
        memset(input_room_name, 0x00, 8);    
        printf("Room name: ");
        scanf("%7s", input_room_name);

        memset(input_user_name, 0x00, 8); 
        printf("User name: ");
        scanf("%7s", input_user_name);

        room_name_len = strlen((const char*)input_room_name);
        user_name_len = strlen((const char*)input_user_name);
 
        status = make_new_chatroom
                (input_room_name, room_name_len,input_user_name, user_name_len);

        if(status)
            printf("[ERR] RTF User Spawner: New chatroom could not be made.\n");
        else
            printf("[OK]  RTF User Spawner: New chatroom made successfully!\n");

        while(1){
            memset(message, 0x00, 128);                                          
            printf("Send a message: ");                                          
            scanf("%127s", message);                             
            printf("[DEBUG] User spawner: [MAKE] reached send_text() call.\n");         
            printf("[DEBUG] User spawner: [MAKE] msg_len: %lu\n"                        
                   ,(uint64_t)strlen((const char*)message)                       
                  );                                                             
            printf("[DEBUG] User spawner: [MAKE] message: %s\n", message);                 
            send_text(message, (uint64_t)strlen((const char*)message));  
        }
    }
    if(user_option == 2){
        printf("Pick a room name and user name, up to 7 characters each.\n");

        memset(input_room_name, 0x00, 8);
        printf("Room name: ");
        scanf("%7s", input_room_name);

        memset(input_user_name, 0x00, 8);
        printf("User name: ");
        scanf("%7s", input_user_name);

        room_name_len = strlen((const char*)input_room_name);
        user_name_len = strlen((const char*)input_user_name);

        status = join_chatroom
               (input_room_name, room_name_len, input_user_name, user_name_len);

        if(status)
            printf("[ERR] RTF User Spawner: Chat room could not be joined.\n");
        else
            printf("[OK]  RTF User Spawner: Joined chatroom successfully!\n\n");
        
        while(1){
            memset(message, 0x00, 128);
            printf("Send a message: ");
            scanf("%127s", message);
            printf("[DEBUG] User spawner: [JOIN] reached send_text() call.\n");
            printf("[DEBUG] User spawner: [JOIN] msg_len: %lu\n"
                   ,(uint64_t)strlen((const char*)message)
                  );
            printf("[DEBUG] User spawner: [JOIN] message: %s\n", message);
            send_text(message, (uint64_t)strlen((const char*)message));
        }
    }

    return;
}

int main(void){

    init_communication = ipc_init_communication;
    transmit_payload   = ipc_transmit_payload;
    receive_payload    = ipc_receive_payload;

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

    free(full_save_dir);

    if(status){
        printf("\n[ERR] User Spawner: login() failed.\n\n");
        exit(1);
    }
    
    printf("\n[OK]  User Spawner: Login completed successfully!\n\n");

    user_loop();


    return 0;
}
