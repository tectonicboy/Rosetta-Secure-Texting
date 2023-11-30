#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>


#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include "net_lib.h"
#include "server_aux.h"

#include "bigint.h"

struct chat_room{
    uint8_t room_guests_ix[MAX_ACTIVE_USERS];
    uint8_t smallest_free_guest_ix;
    uint8_t guests_counter;
    uint8_t room_owner_ix;
    char room_name[MAX_ROOM_NAME_SIZ + 1];
    char room_pass[MAX_ROOM_PASS_SIZ + 1];
};

struct connected_client{
    unsigned long client_IP;
    char username[MAX_USER_NAME_SIZ + 1];
    uint16_t pending;
    char pend_msgs[ (MAX_USER_NAME_SIZ + 1 + MAX_MSG_LEN + 1) * 256];
    uint32_t client_FD;
    uint8_t room_ix;
    uint8_t room_closed;
}; 

struct connected_client active_users[MAX_ACTIVE_USERS];
struct chat_room active_rooms[MAX_ACTIVE_ROOMS];

uint8_t users_counter = 0, room_counter = 0;

uint8_t active_room_indices[MAX_ACTIVE_ROOMS];
uint8_t smallest_free_room = 1;

uint8_t active_user_indices[MAX_ACTIVE_USERS];
uint8_t smallest_free_user = 1;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

uint8_t Create_New_User(unsigned long IP_addr, char* username){

    uint8_t ret;

    if(smallest_free_user > MAX_ACTIVE_USERS - 1){
        printf("[OK] Server: Not enough space to make a new user!\n");
        return 0;
    }
    
    printf("Create_New_User(): Creating w/ name: %s\n", username);
    
    active_users[smallest_free_user].client_IP = IP_addr;
    
    strncpy(active_users[smallest_free_user].username, username, MAX_USER_NAME_SIZ + 1);
    
    ++users_counter;

    active_user_indices[smallest_free_user] = 1;
    
    ret = smallest_free_user;
    
    printf("Created user in slot index: %u\n", smallest_free_user);
    ++smallest_free_user;
    
    while(active_user_indices[smallest_free_user]){
        ++smallest_free_user;
    }
    
    printf("Next free user slot index: %u\n", smallest_free_user);
    
    return ret;
}



void Delete_User(uint8_t user_ix){
    memset(&(active_users[user_ix]), 0x00, sizeof(struct connected_client));
    
    --users_counter;
    
    active_user_indices[user_ix] = 0;
    
    if(user_ix < smallest_free_user){
        smallest_free_user = user_ix;
    }
    
    return;        
}


uint8_t Create_New_Room(char* owner_uname, char* room_name, char* room_pass){

    uint8_t ret;

    if(smallest_free_room > MAX_ACTIVE_ROOMS - 1){
        printf("[OK] Server: Not enough space to make a new room!\n");
        return 0;
    }
    /* Find the owner user's existing user structure. */
    for(uint8_t i = 1; i < MAX_ACTIVE_USERS; ++i){
	    if(strcmp(owner_uname, active_users[i].username) == 0){
	        printf("CREATE_ROOM(): User's name to create their room: %s\n"
	               ,active_users[i].username);
		    active_rooms[smallest_free_room].room_owner_ix = i;  
		    active_users[i].room_ix = smallest_free_room;
		}
	}
    strncpy(active_rooms[smallest_free_room].room_name, room_name, MAX_ROOM_NAME_SIZ + 1);
    strncpy(active_rooms[smallest_free_room].room_pass, room_pass, MAX_ROOM_PASS_SIZ + 1);
    
    ++room_counter;

    active_room_indices[smallest_free_room] = 1;

    printf("[OK] Server: Created a new room successfully!\n"
           "             Room_Owner: %s\n"
           "             Room_Name : %s\n"
           "             Room_Pass : %s\n"
           "             Room_Slot : %u\n\n"
          , active_users[(active_rooms[smallest_free_room].room_owner_ix)].username
          , active_rooms[smallest_free_room].room_name
          , active_rooms[smallest_free_room].room_pass
          , smallest_free_room
    );

    ret = smallest_free_room;

    ++smallest_free_room;
    
    while(active_room_indices[smallest_free_room]){
        ++smallest_free_room;
    }
    
    printf("Next free ROOM SLOT INDEX: %u\n", smallest_free_room);
    
    return ret;
}

uint8_t Join_Room(uint8_t room_ix, uint8_t user_ix){

    printf("JOIN_ROOM passed user_ix: %u\n", user_ix);

    if(active_rooms[room_ix].guests_counter > MAX_ACTIVE_USERS - 1){
        printf("[OK] Server: Not enough guest space to join this room!\n");
        return 0;
    }
    
    printf("Join_Room(): Joining room w/ name: %s\n", active_rooms[room_ix].room_name);
    printf("Join_Room(): The user joining is : %s\n", active_users[user_ix].username);
    
    active_rooms[room_ix].room_guests_ix[active_rooms[room_ix].smallest_free_guest_ix] = user_ix;
    active_users[user_ix].room_ix = room_ix;

    ++active_rooms[room_ix].guests_counter;
    
    printf("User slot[%u] joined room slot[%u] successfully.\n", user_ix, room_ix);
    ++active_rooms[room_ix].smallest_free_guest_ix;
    
    while(active_rooms[room_ix].room_guests_ix[active_rooms[room_ix].smallest_free_guest_ix]){
        ++active_rooms[room_ix].smallest_free_guest_ix;
    }
    
    printf("Next free guest slot in this room: %u\n", active_rooms[room_ix].smallest_free_guest_ix);
    
    return 1;        
}

void Delete_Room(uint8_t room_ix){

    /* Delete the user with index owner and indices the room guests. */
    
    Delete_User(active_rooms[room_ix].room_owner_ix);
    
    for(uint8_t j = 0; j < MAX_ACTIVE_USERS; ++j){
        if( active_rooms[room_ix].room_guests_ix[j] > 0){
            
            Delete_User(active_rooms[room_ix].room_guests_ix[j]); 
        }
    }

    memset(&(active_rooms[room_ix]), 0x00, sizeof(struct chat_room));     
    --room_counter;
    
    active_room_indices[room_ix] = 0;
    
    if(room_ix < smallest_free_room){
        smallest_free_room = room_ix;
    }
     
    return;        
  
}


void* Process_HTTP_Req(void* thread_arg){

    pthread_mutex_lock(&lock);
    
    unsigned long temp_IP = *((unsigned long*)(((uint32_t*)(thread_arg)) + 1));
    
    uint32_t servervars_start_i = 0
            ,client_socket = *((uint32_t*)(thread_arg))
            ,sent, chat_msg_ix = 0;
            
	int64_t  bytes_read; 
	
	uint64_t k;
	    
	uint8_t room_name_exists_flag = 0
	       ,i, j, username_taken_flag = 0, passwords_dont_match_flag = 0
	       ,room_to_join_ix = 0, user_to_join_ix = 0, exit_outer_flag = 0
	       ,msg_sender_ix = 0, msg_sender_room_ix = 0;
	       	
	char *http_vars, *requested_fname, *client_message,
	     curr_msg_username[MAX_USER_NAME_SIZ + 1], sent_room_name[MAX_ROOM_NAME_SIZ + 1],
	     sent_username[MAX_USER_NAME_SIZ + 1], sent_password[MAX_ROOM_PASS_SIZ + 1],
	     full_message[2048];

	
	memset(curr_msg_username, 0x00, MAX_USER_NAME_SIZ + 1);
	memset(sent_room_name, 0x00, MAX_ROOM_NAME_SIZ + 1);
	memset(sent_username, 0x00, MAX_USER_NAME_SIZ + 1);    
	memset(sent_password, 0x00, MAX_ROOM_PASS_SIZ + 1); 
	memset(full_message, 0x00, 2048);
	    
	if(
	      posix_memalign((void*)&http_vars,        64, 4096 ) 
	   || posix_memalign((void*)&requested_fname,  64, 64  ) 
	   || posix_memalign((void*)&client_message,   64, 4096) 
	  )
	{
	    printf("[ERR]Server: Critical - Memory error on line %d. Aborting.\n", __LINE__); 
	    return NULL;
	}

        //Reset stuff.
		sent = 0; 
		k = 5;
		memset(http_vars, 0x0, 4096); 
		memset(requested_fname, 0x0, 64); 
		memset(client_message, 0x0, 4096); 

		if((bytes_read = recv(client_socket, client_message, 4096, 0)) == -1){
		    printf("[ERR] Server: Couldn't peek at first bytes of HTTP request.\n");
		    goto label2;
		}
		/*printf("[OK] Server: Obtained HTTP request's first [%ld] bytes.\n", bytes_read);*/
		/*printf("CLIENT SENT US THIS:\n\n%s\n\n", client_message);*/
		/* Obtain HTTP variables embedded at the end of the HTTP request */
		if( ( servervars_start_i = Extract_HTTP_Variables(client_message, http_vars) ) < 4096){
		    printf("Captured vars:%s\n\n", http_vars);
		    switch(http_vars[0]){

		    /* User wants to create a room and has sent us the name they wanted for it. */
		    case 'A':{
		    
		        printf("\n\nHTTP variables received.\nCase is A.\nCaptured vars:%s\n\n", http_vars);
		        
		        /* Get the room name that the website user entered. */
		        for(i = 2; http_vars[i] != '-' && i < 17; ++i){
		            sent_room_name[i-2] = http_vars[i];    
		        }

                /* Get the username that the website user entered. */
		        for(j = ++i; http_vars[j] != '-' && j < (i + 15); ++j){
		            sent_username[j-i] = http_vars[j];    
		        }
		    
                /* Get the password that the website user entered. */
		        for(i = ++j; http_vars[i] != 0 && i < (j + 15); ++i){
		            sent_password[i-j] = http_vars[i];    
		        }
	        
		        printf("Client wants to have this room password: \n%s\n", sent_password);      
		        printf("Client wants to have this username: \n%s\n", sent_username);
		        printf("Client wants to create this room:\n%s\n", sent_room_name);		        
		        
		        /* Decide if this room name is available or not. */
		        if(room_counter){
		            for(i = 1; i < MAX_ACTIVE_ROOMS; ++i){
		                /* if there's an active room in slot i, check its name. */
		                if(active_room_indices[i]){
		                    if(strcmp(active_rooms[i].room_name, sent_room_name) == 0){
		                        room_name_exists_flag = 1;
		                        printf("[OK] Server: Room name already used: %s\n", sent_room_name);
		                        break;    
		                    }
		                }
		            }
		        }
		        
		        if(room_name_exists_flag){
		            if( send(client_socket, "room_name_taken", 15, 0 ) == -1){
				            printf("[ERR] Server: Couldn't send room-name-unavailable message.\n");
				            break;
			        }
			        sent = 1; 
			        printf("[OK] Server: Told the client the room name is not available.\n");
			        break; 	
			    }


                /* Decide if this user name is available or not. */
		        if(users_counter){
		            for(i = 1; i < MAX_ACTIVE_USERS; ++i){
		                /* if there's an active user in slot i, check their name. */
		                if(active_user_indices[i]){
		                    if(strcmp(active_users[i].username, sent_username) == 0){
		                        username_taken_flag = 1;
		                        break;    
		                    }
		                }
		            }
		        }

		        if(username_taken_flag){
		            if( send(client_socket, "user_name_taken", 15, 0 ) == -1){
				        printf("[ERR] Server: Couldn't send username-unavailable message.\n");
				        break;
			        }
			        sent = 1; 
			        printf("[OK] Server: Told the client the user name is not available.\n");
			        break; 	
			    }

                if( ! (Create_New_User(temp_IP, sent_username)) ){
		            if( send(client_socket, "no_users_space", 14, 0 ) == -1){
				        printf("[ERR] Server: Couldn't send no user space left message.\n");
				        break;
			        }
			        sent = 1; 
			        printf("[OK] Server: Told the client there's no more space for users ATM.\n");
			        break; 	                    
                }
                

                if( ! Create_New_Room(sent_username, sent_room_name, sent_password) ){
		            if( send(client_socket, "no_rooms_space", 14, 0 ) == -1){
				        printf("[ERR] Server: Couldn't send no rooms space left message.\n");
				        break;
			        }
			        sent = 1; 
			        printf("[OK] Server: Told the client there's no more space for rooms ATM.\n");
			        break; 	                    
                }



			    if( send(client_socket, "yes", 3, 0 ) == -1){
				    printf("[ERR] Server: Couldn't send room success message.\n");
				    break;
			    }
			    sent = 1; 
			    printf("[OK] Server: Told the client the room and user names are available.\n");       		        

		        break; /* End of case 'A' */
		    }
		    
		    
		    
		    
		    
		    
            /* User tried to join a room. */
            case 'B':{
                printf("\n\nHTTP variables received.\nCase is B.\nCaptured vars:%s\n\n", http_vars);
		        
		        /* Get the room name that the website user entered. */
		        for(i = 2; http_vars[i] != '-' && i < 17; ++i){
		            sent_room_name[i-2] = http_vars[i];    
		        }

                /* Get the username that the website user entered. */
		        for(j = ++i; http_vars[j] != '-' && j < (i + 15); ++j){
		            sent_username[j-i] = http_vars[j];    
		        }
		    
                /* Get the password that the website user entered. */
		        for(i = ++j; http_vars[i] != 0 && i < (j + 15); ++i){
		            sent_password[i-j] = http_vars[i];    
		        }
	        
		        printf("Client wants to join room w/ password: \n%s\n", sent_password);      
		        printf("Client wants to have this username: \n%s\n", sent_username);
		        printf("Client wants to join this room name:\n%s\n", sent_room_name);		        
		        
		        /* Decide if this room name exist or not*/
		        if(room_counter){
		            for(i = 1; i < MAX_ACTIVE_ROOMS; ++i){
		                /* if there's an active room in slot i, check its name. */
		                if(active_room_indices[i]){
		                    if(strcmp(active_rooms[i].room_name, sent_room_name) == 0){
		                        room_name_exists_flag = 1;
		                        printf("[OK] Server: Room name exists: %s\n", sent_room_name);
                                room_to_join_ix = i;
		                        /* Decide if the room's password matches the entered password. */
		                        if( ! strcmp(active_rooms[i].room_pass, sent_password) == 0){
		                            printf("[OK] Server: Room passwords don't match.\n");  
		                            passwords_dont_match_flag = 1; 
		                        }

		                        break;    
		                    }
		                }
		            }
		        }
		        
		        if( ! room_name_exists_flag ){
		            if( send(client_socket, "room_name_not_found", 19, 0 ) == -1){
				            printf("[ERR] Server: Couldn't send room_name_not_found message.\n");
				            break;
			        }
			        sent = 1; 
			        printf("[OK] Server: Told the client the room name was not found.\n");
			        break; 	
			    }

                if( passwords_dont_match_flag ){
		            if( send(client_socket, "passwords_dont_match", 20, 0 ) == -1){
				            printf("[ERR] Server: Couldn't send PWDs_dont_match message.\n");
				            break;
			        }
			        sent = 1; 
			        printf("[OK] Server: Told the client the passwords did not match.\n");
			        break; 	                    
                }

                
                /* Decide if this user name is available or not. 
                 *
                 * Note: Checking if there are
                 *       users to begin with is pointless because if we got to this point in this
                 *       SWITCH case, it means the room they wanna join was found, which means there
                 *       is at least one user in the website.
                 */

	            for(i = 1; i < MAX_ACTIVE_USERS; ++i){
	                /* if there's an active user in slot i, check their name. */
	                if(active_user_indices[i]){
	                    if(strcmp(active_users[i].username, sent_username) == 0){
	                        username_taken_flag = 1;
	                        break;    
	                    }
	                }
	            }


		        if(username_taken_flag){
		            if( send(client_socket, "user_name_taken", 15, 0 ) == -1){
				        printf("[ERR] Server: Couldn't send username-unavailable message.\n");
				        break;
			        }
			        sent = 1; 
			        printf("[OK] Server: Told the client the user name is not available.\n");
			        break; 	
			    }
                
                

                if( ! (user_to_join_ix = Create_New_User(temp_IP, sent_username)) ){
		            if( send(client_socket, "no_users_space", 14, 0 ) == -1){
				        printf("[ERR] Server: Couldn't send no user space left message.\n");
				        break;
			        }
			        sent = 1; 
			        printf("[OK] Server: Told the client there's no more space for users ATM.\n");
			        break; 	                    
                }
                

                if( ! Join_Room(room_to_join_ix, user_to_join_ix) ){
		            if( send(client_socket, "no_guests_space", 15, 0 ) == -1){
				        printf("[ERR] Server: Couldn't send no guests space message.\n");
				        break;
			        }
			        sent = 1; 
			        printf("[OK] Server: Told the client there's no more space for guests ATM.\n");
			        break; 	                    
                }

			    if( send(client_socket, "yes", 3, 0 ) == -1){
				    printf("[ERR] Server: Couldn't send join_room_success message.\n");
				    break;
			    }
			    sent = 1; 
			    printf("[OK] Server: Told the client they successfully joined the room.\n");       		        

		        break; /* End of case 'B' */
            }



            /* User wants to exit or delete the chat room. */
            case 'C':{
            
                /* Get the username of whoever wants to exit / delete a chat room. */
		        for(i = 2; http_vars[i] != 0 && i < 17; ++i){
		            sent_username[i-2] = http_vars[i];    
		        }
		        printf("[C]: Fetched username: %s\n",sent_username);
		        
                /* This particular HTTP request won't expect a response from our server. */
                sent = 1;
                
                /* Find out whether this user is the owner of a room. */
                /* If they're just a guest, find the room they're about to leave. */        
            
                for(i = 1; i < MAX_ACTIVE_ROOMS; ++i){
                    if(   active_room_indices[i] 
                       && 
                          strcmp(
                               active_users[active_rooms[i].room_owner_ix].username
                              ,sent_username 
                          ) == 0
                      )       
                    {
                        /* We wanna delete the room in question. */
                        Delete_Room(i);
                        msg_sender_room_ix = i;
                        printf("[OK] Server: Deleted Room [%u] successfully.\n", i);
                        exit_outer_flag = 1;
                        break;
                    }    
                }
                
                if(exit_outer_flag){ break; }
            
                /* If we got to this point, the user is a guest. Find the room and exit it. */
            
                printf("[OK] Server: Client who pressed X in a room is not a room owner.\n");


                for(j = 0; j < MAX_ACTIVE_USERS; ++j){
                    if( (active_rooms[msg_sender_room_ix]).room_guests_ix[j]
                       &&
                       strcmp(
                               active_users[active_rooms[msg_sender_room_ix].room_guests_ix[j]].username
                              ,sent_username
                              ) == 0
                      )
                    {
                        /* Make this user leave the room and no longer be a guest. */

                        if(j < active_rooms[msg_sender_room_ix].smallest_free_guest_ix){
                            active_rooms[msg_sender_room_ix].smallest_free_guest_ix = j;
                        }
                        --active_rooms[msg_sender_room_ix].guests_counter;  
                        
                        Delete_User(active_rooms[msg_sender_room_ix].room_guests_ix[j]);
                        
                        active_rooms[msg_sender_room_ix].room_guests_ix[j] = 0;
                        
                        printf("[OK] Server: Guest [%u] exited room [%u].\n", j, msg_sender_room_ix);  
                         
                        exit_outer_flag = 1;
                        
                        break;
                    } 


                    if(exit_outer_flag){
                        break;
                    }
                }
                if(!exit_outer_flag){
                    printf("[OK] Server: No rooms found which they're a guest in, either.\n");
                }
                break; /* End of case 'C' */
            }
 
		    case 'M':{
		        /*
		         * In case an attacker crafted a packet that bypassed the browser's
		         * control of the message length, inject a
		         * null terminator at the end of the message here. 
		         */
		        http_vars[4097] = 0;
		        
		        /* Get the username of whoever sent a message in the chat room. */
		        for(i = 2; http_vars[i] != '-' && i < 17; ++i){
		            sent_username[i-2] = http_vars[i];    
		        }
		        
		        chat_msg_ix = ++i;
		        
		        printf("[M]: Fetched username: %s\n",sent_username);
		        printf("Printing http_vars at offset chat_msg_ix (where chat msg should be):\n%s"
		              ,http_vars + chat_msg_ix
		        );
		        
		        /* Find the username of whoever sent this message */
		        for(i = 1; i < MAX_ACTIVE_USERS; ++i){
		            if( 
		                active_user_indices[i] 
		              && 
                        strcmp(
                               active_users[i].username
                              ,sent_username
                              ) == 0
		              )
		            
		             { 
		                printf("[M]: Username of the MSG sender: %s\n", active_users[i].username);
		                strcpy(curr_msg_username, active_users[i].username);
		                msg_sender_ix = i;
		                break;
		            }
		        }  
		        
		        
		        
		        /* Craft the full message with the username who sent it. */
		        strcpy(full_message, curr_msg_username);
		        strcpy(full_message + strlen(curr_msg_username), ": \0");
		        strcpy(full_message + strlen(curr_msg_username) + 2, http_vars + chat_msg_ix);
		        
		        printf("[M]: Constructed the pending MSG:\n%s(on new line here?)", full_message);
		         
		        for(i = 1; i < MAX_ACTIVE_USERS; ++i){
		            if(  active_user_indices[i] 
		               &&
		                 active_users[i].room_ix == active_users[msg_sender_ix].room_ix
		              )
		              {
		                printf("[M]: Found a user who will need to see that same MSG!!\n");
		                strcpy(
		                       active_users[i].pend_msgs
                                 +
                                 (
                                   active_users[i].pending 
                                   * 
                                   (MAX_USER_NAME_SIZ + 1 + MAX_MSG_LEN + 1) /* name:msg\0 */
                                 )
		                      ,full_message
		                      );	
		                ++active_users[i].pending;	                             
		              }   		          
		        }
		        /* This case doesn't send any response. */
		        sent = 1;
		        break;
		    }
		    
		    /* This HTTP variable '?' gets sent by every chatting user 10 times a second */
		    /* in order to check whether there's any messages this user's browser hasn't */ 
		    /* displayed yet.                                                            */
		    case '?':{
		    
		    	/* Get the username of whoever is asking for undisplayed messages. */
		        for(i = 2; http_vars[i] != '-' && i < 17; ++i){
		            sent_username[i-2] = http_vars[i];    
		        }
		        printf("[?]: Fetched username: %s\n",sent_username);
		        
		        for(i = 1; i < MAX_ACTIVE_USERS; ++i){
		            printf("[?] Checking [%u]th user's username: %s\n", i, active_users[i].username);
		            printf("[?]The %u-th global index in the ACTIVITY USER array: %u\n"
		                  ,i
		                  ,active_user_indices[i]
		            );
		            if( 
		                active_user_indices[i] 
		              && 
                        (   
                            strcmp(
                               active_users[i].username
                              ,sent_username
                              ) == 0
                        )
		              )
		            {
		                printf("[?] Found polling user's username: %s\n", active_users[i].username);
		                if(active_users[i].pending > 0){
                            printf("[?]: YES - case ? found a pending message to send!\n");
                            printf("[?]: This users PENDING msgs: %u\n", active_users[i].pending);
		                    if(
		                         send(
			                         client_socket
			                        ,active_users[i].pend_msgs
			                                    +
			                                    (
			                                     (active_users[i].pending - 1) 
			                                     * 
			                                     (MAX_USER_NAME_SIZ + 1 + MAX_MSG_LEN + 1)
			                                    )
			                        ,(MAX_USER_NAME_SIZ + 1 + MAX_MSG_LEN + 1)
			                        ,0
			                        ) == -1
			                  )
			                  {
			                    printf("[ERR] Server: Couldn't transmit pending message.\n");
			                    break;
			                  }
			                sent = 1;
			                memset(
			                        active_users[i].pend_msgs
			                                +
			                                (
			                                 (active_users[i].pending - 1) 
			                                 * 
			                                 (MAX_USER_NAME_SIZ + 1 + MAX_MSG_LEN + 1)
			                                )			                        
			                        ,0x00
			                        ,(MAX_USER_NAME_SIZ + 1 + MAX_MSG_LEN + 1)
			                      );
			                      
			                --active_users[i].pending;   
			                
		                } 
		                else{
		                    if( send(client_socket, "no", 2, 0 ) == -1){
				                printf("[ERR] Server: Couldn't send no pending msgs msg.\n");
				            }
				            sent = 1;
				        }
				        break;
			        }   
		        }
		        
		        /* We didnt find a user slot with that username anymore. Deleted/exited room. */
		        if(!sent){
                    if( send(client_socket, "deleted", 7, 0 ) == -1){
		                printf("[ERR] Server: Couldn't send user-deleted msg.\n");
		            }
		            sent = 1;		            
		        }
		        
		        break;     
		    }        
		    default: break;
		    }
		} 
	
		/* If the client requested a file, try finding and sending it back. */
		if(client_message[0] == 'G'){
		
			while(
			        !(
			             client_message[k+1] == 'H' && client_message[k+2] == 'T'
			          && client_message[k+3] == 'T' && client_message[k+4] == 'P'
			         )
			     )
			{
				requested_fname[k-5] = client_message[k];
				++k;
				if(k > 64){break;}
			}
			
			/*==============================================================*/
			/* If the web client requested a file and we know its name,     */
			/* check if the name matches that of any of the files that      */
			/* we have on our server that we can potentially send to a web  */
			/* client, and if we find a match, attempt to send it.          */
			/*==••••••============================================================*/
			if(*requested_fname){
				printf("[OK] Server: Identified requested file: [%s]\n", requested_fname);
				
				for(size_t i = 0; i < SITE_FILES; ++i){
				
					if( strcmp(site_files[i]->fname, requested_fname) == 0 ){
					
						if( send(
						         client_socket
						        ,site_files[i]->fbuf
						        ,site_files[i]->fsize
						        ,0
						        ) == -1
						  )
						{
						    printf("[ERR] Server: Couldn't send requested file.\n");
						}
						else{
						    printf(
						            "[OK] Server: Sent file [%s] to the client.\n"
						           ,site_files[i]->fname
						          );
						    sent = 1;
					    }					
					}
				} 
			}
		}
		
		label2:
        if(!sent){
            printf("[OK] Server: Sending index.html to client.\n");
			if(send(client_socket, site_files[0]->fbuf, site_files[0]->fsize, 0) < 0){
			    printf("[ERR] Server: Could not send index.html to client.\n");
			}
			else{
			    printf("[OK] Server: Sent index.html to client.\n");
			}
		}
		
		close(client_socket);
		
    free(http_vars); 
	free(requested_fname); 
	free(client_message); 
	free(thread_arg);
	
	pthread_mutex_unlock(&lock);
	
	return NULL;
}

int main(){

/**********  Initialize server-wide state for all files to be sent to clients.  *********/
    if( init_files() ) {
        printf("[ERR] Server: Critical - could not set up server files. Aborting.\n");
        return 1;
    }

/*********  Create the socket, bind a name to it and make it listen on port 80  *********/
	int port = 80, server_socket;
	
    struct sockaddr_in server_address = { .sin_family = AF_INET
	                                     ,.sin_port = htons(port)
	                                     ,.sin_addr.s_addr = INADDR_ANY
	                                    };
	                                             
	if( (server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1){
	    printf("[ERR] Server: Critical - could not open server socket. Aborting.\n");
	    return 1;
	}
	         
	int optval1 = 1, optval2 = 2;
	
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEPORT, &optval1, sizeof(optval1));
	
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval2, sizeof(optval2));
	                  
	if( 
	    (bind(
	       server_socket
	      ,(struct sockaddr*)&server_address
	      ,sizeof(server_address)
	    )) == -1
	  )
	  {
	    if(errno != 13){
	        printf("[ERR] Server: Critical - bind() failed. Errno != 13. Aborting.\n");
	        return 1;
	    }
	  }
	   
	if( (listen(server_socket, 16)) == -1){
		printf("[ERR] Server: Critical - could not begin listening. Aborting.\n");
	    return 1;
	}
	
/************************  END of Sockets API initialization   **************************/		

		
/**************************  Variables used for serving loop  ***************************/  

    socklen_t clientLen = sizeof(struct sockaddr_in);
    struct sockaddr_in client_address;

    pthread_t thread_ids[128];
    void**    thread_arg_ptrs[128];
   
    memset(active_users, 0x00, MAX_ACTIVE_USERS * sizeof(struct connected_client));
    memset(active_rooms,   0x00, MAX_ACTIVE_ROOMS * sizeof(struct chat_room));
    
    
    /*  Array of indices that tells us which rooms are free and which ones are not.
     *
     *  When a room is created, smallest_free_room is used to determine which slot
     *  in the index array to set to 1. Then that same slot is used to initialize
     *  the actual chat_room structure in the actual array of chat_rooms. Then, the
     *  new value of next_free_room is decided by checking the next indices in the 
     *  room index array for a zero value, as long as the active_rooms counter didn't 
     *  just reach MAX_ACTIVE_ROOMS. If so, it's set to MAX_ACTIVE_ROOMS + 1.
     * 
     *  When a room is deleted, the actual structure in the array of chat_rooms is
     *  zeroed and if this room's slot in the room index array was smaller than the
     *  current value of next_free_room, then next_free_room is set to this slot,
     *  while the slot pointed to by the previous value of next_free_room remains 0
     *  (and the actual structure with the same old index is still zero'd) so that 
     *  it's still visible to the algorithm as a free room to be used in the future.
     *
     *  Room index 0 and User index 0 are never used because we want room guest indices
     *  to be initializable to 0. If we use user index 0 as an actual user, that breaks
     *  the logic of maintaining every room's guest indices if they get initialized to 0.
     * 
     */
    memset(active_room_indices, 0x00, MAX_ACTIVE_ROOMS * sizeof(uint8_t));
 
    /* Exact same logic for keeping track of which user slots are free and which are taken. */
    memset(active_user_indices, 0x00, MAX_ACTIVE_USERS * sizeof(uint8_t));

    uint8_t thread_counter = 0;
    

/* The serving loop. */

    while(1){
		
		printf("\n\t***** Listening for HTTP requests on port %d *****\n\n", port);

        if(thread_counter == 128) {
            thread_counter = 0;
        }

        thread_arg_ptrs[thread_counter] = malloc(sizeof(uint32_t) + sizeof(unsigned long));
        
		*((uint32_t*)(thread_arg_ptrs[thread_counter]))
		    = 
		    accept( server_socket
		           ,(struct sockaddr*)(&client_address)
		           ,&clientLen
		          );
           
        *((unsigned long*)( ((uint32_t*)(thread_arg_ptrs[thread_counter])) + 1)) 
        = 
        client_address.sin_addr.s_addr;

        output_red();
        printf("Creating thread[%u]\n\tfd = %u\n\tIP = %lu\n\n"
              ,thread_counter
              ,*((uint32_t*)(thread_arg_ptrs[thread_counter]))
              ,*((unsigned long*)( ((uint32_t*)(thread_arg_ptrs[thread_counter])) + 1)) 
        );
        output_rst();
        
        pthread_create(
                        &(thread_ids[thread_counter])
                        ,NULL
                        ,Process_HTTP_Req
                        ,(void*)thread_arg_ptrs[thread_counter]
                       );   
                       
        ++thread_counter;
	}
	
	free(site_files);
	
    return 0;
}









