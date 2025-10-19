#include "../client/network-code/client-primary-functions.h"

void user_loop(void){

    int           user_option;
    char          input_user_option[1];
    unsigned char input_room_name[8];
    unsigned char input_user_name[8];
    unsigned char message[128];
    int           room_name_len;
    int           user_name_len;
    int           scanf_status;
    uint8_t       status;
    const char* GUI_string_helper = ": ";
    char name_with_msg_string[127 + 2 + SMALL_FIELD_LEN];

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
  
            /* This boolean is for handling the case where the polling thread
             * told us that the room owner has closed the chatroom and we should
             * no longer be allowed to send messages in it, but it happened not
             * while we are blocked in a scanf() call (which the polling thread
             * would interrupt by sending a signal for which this thread has
             * installed a signal handler for), but while running the other code
             * in the infinite loop, before it gets blocks on scanf again.
             */
            pthread_mutex_lock(&poll_mutex);
            if(texting_should_stop == 1){
                printf("[OK] RTF User Spawner: Cleanly stopped scanf() loop\n");
                pthread_mutex_unlock(&poll_mutex);
                pthread_join(poller_threadID, NULL);
                printf("[DEBUG] RTF User Spawner: Got past pthread_join() !\n");
                break;
            }
            pthread_mutex_unlock(&poll_mutex);

            memset(message, 0x00, 128);
            printf("Send a message: ");

            scanf_status = scanf("%127s", message);

            if(scanf_status == -1 && errno == EINTR){
                printf("[OK] RTF User Spawner: Cleanly stopped scanf() loop\n");
                pthread_join(poller_threadID, NULL);
                break;
            }
            else if(strncmp((const char*)message, "__logout__", 10) == 0){           
                status = logout();                                              
                if(status){                                                     
                    printf("[ERR] User Spawner: Error during Logout().\n");     
                }                                                               
                else{                                                           
                    printf("[OK]  User Spawner: Successfully logged out.\n");   
                }                                                               
                exit(1);                                                          
            }
            else if(strncmp((const char*)message, "__leaveroom__", 13) == 0){
                status = leave_chatroom();
                if(status)
                    printf("[ERR] User Spawner: Bad leave_chatroom() call.\n");
                else
                    printf("[OK]  User Spawner: Leave chatroom: COMPLETED.\n");
                break;
            }                        
            printf("[DEBUG] User spawner: [MAKE] reached send_text() call.\n"); 
            printf("[DEBUG] User spawner: [MAKE] msg_len: %lu\n"                
                   ,(uint64_t)strlen((const char*)message)                      
                  );                                                            
            printf("[DEBUG] User spawner: [MAKE] message: %s\n", message);      
            send_text(message, (uint64_t)strlen((const char*)message));  

            /* Construct the string with name and message to be displayed on the GUI. */
            memset(name_with_msg_string, 0x00, 127 + 2 + SMALL_FIELD_LEN);
            memset(name_with_msg_string, 0x20, (SMALL_FIELD_LEN - strlen( (const char*)(input_user_name) )));
            memcpy(name_with_msg_string + (SMALL_FIELD_LEN - strlen( (const char*)(input_user_name) )), input_user_name, strlen( (const char*)(input_user_name) ));
            memcpy(name_with_msg_string + SMALL_FIELD_LEN, GUI_string_helper, 2);
            memcpy(name_with_msg_string + SMALL_FIELD_LEN + 2, message, strlen((const char*)message));
            printf("%s\n", name_with_msg_string);

        }
        goto label_begin_user;
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

            /* This boolean is for handling the case where the polling thread
             * told us that the room owner has closed the chatroom and we should
             * no longer be allowed to send messages in it, but it happened not
             * while we are blocked in a scanf() call (which the polling thread
             * would interrupt by sending a signal for which this thread has
             * installed a signal handler for), but while running the other code
             * in the infinite loop, before it gets blocks on scanf again.
             */
            pthread_mutex_lock(&poll_mutex);
            if(texting_should_stop == 1){
                printf("[OK] RTF User Spawner: Cleanly stopped scanf() loop\n");
                pthread_mutex_unlock(&poll_mutex);
                pthread_join(poller_threadID, NULL);
                printf("[DEBUG] RTF User Spawner: got past pthread_join() !\n");
                break;
            }
            pthread_mutex_unlock(&poll_mutex);

            memset(message, 0x00, 128);
            printf("Send a message: ");

            scanf_status = scanf("%127s", message);

            if(scanf_status == -1 && errno == EINTR){
                printf("[OK] RTF User Spawner: Cleanly stopped scanf() loop\n");
                pthread_join(poller_threadID, NULL);
                break;
            }
            else if(strncmp((const char*)message, "__logout__", 10) == 0){
                status = logout();
                if(status)
                    printf("[ERR] User Spawner: Error during Logout().\n");
                else
                    printf("[OK]  User Spawner: Successfully logged out.\n");
                exit(1);
            }
            else if(strncmp((const char*)message, "__leaveroom__", 13) == 0){
                status = leave_chatroom();
                if(status)
                    printf("[ERR] User Spawner: Bad leave_chatroom() call.\n");
                else
                    printf("[OK]  User Spawner: Leave chatroom: COMPLETED.\n");
                break;
            }

            /* Send it to everyone in the chatroom. */
            send_text(message, (uint64_t)strlen((const char*)message));

            /* Display it in that user's own client too */
            
            /* Construct the string with name and message to be displayed on the GUI. */
            memset(name_with_msg_string, 0x00, 127 + 2 + SMALL_FIELD_LEN);
            memset(name_with_msg_string, 0x20, (SMALL_FIELD_LEN - strlen( (const char*)(input_user_name) )));
            memcpy(name_with_msg_string + (SMALL_FIELD_LEN - strlen( (const char*)(input_user_name) )), input_user_name, strlen( (const char*)(input_user_name) ));
            memcpy(name_with_msg_string + SMALL_FIELD_LEN, GUI_string_helper, 2);       
            memcpy(name_with_msg_string + SMALL_FIELD_LEN + 2, message, strlen((const char*)message));
            printf("%s\n", name_with_msg_string);
        }
        goto label_begin_user;
    }

    return;
}

int main(void){

    init_communication = ipc_init_communication;
    transmit_payload   = ipc_transmit_payload;
    receive_payload    = ipc_receive_payload;
    end_communication  = ipc_end_communication;

    unsigned char  savefilename[16] = {'\0'};
    unsigned char* full_save_dir = NULL;
    uint8_t        status = 0;
    uint8_t        pw_buf[16] = {0};
    const char*    savedir = "./test-accounts/";

    main_thread_id = pthread_self();

    /* Install a signal handler for SIGUSR1 using sigaction().
     * Allows the poller thread to send us a signal when it receives information
     * that the owner of the chatroom we are in has decided to close it. This
     * signal causes the Test Framework to unblock from the scanf() call for
     * sending text messages in the chatroom. For the GUI version, it alerts
     * the GUI renderer to retract the GUI elements for sending text messages in
     * the chatroom and shows an info box alerting the user.
     *
     * Signal handler  handle_signal_sigusr1()  is in client-primary-functions.h
     *
     * Signal sender is process_msg_51() using pthread_kill().
     */
    struct sigaction sa;

    sa.sa_handler = handle_signal_sigusr1;
    sigemptyset(&sa.sa_mask);

    /* Don't immediately restart syscalls interrupted by this signal. */
    sa.sa_flags = 0;

    /* Install the signal handler. */
    sigaction(SIGUSR1, &sa, NULL);

    printf("[OK] RTF User Spawner: Installed signal handler to stop scanf.\n");

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
