#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cryptolib.h"
#include "bigint.h"

#define SERVER_PORT    54746
#define PRIVKEY_BYTES  40   
#define MAX_CLIENTS    64
#define MAX_PEND_MSGS  1024
#define MAX_CHATROOMS  64
#define MAX_MSG_LEN    1024
#define MAX_SOCK_QUEUE 1024

#define MAGIC_0 0xAD0084FF0CC25B0E


/* Cryptography, users and chatroom related globals. */

/* A bitmask telling the server which client slots are currently free. */
uint64_t clients_status_bitmask = 0;

uint32_t next_free_user_ix = 0;
uint32_t next_free_room_ix = 0;

uint8_t server_privkey[PRIVKEY_BYTES];

struct connected_client{
	uint32_t room_ix;
	uint32_t num_pending_msgs;
	uint8_t* pending_msgs[MAX_PEND_MSGS];
	uint8_t* client_pubkey;
	uint64_t pubkey_siz_bytes;
};

struct chatroom{
	uint32_t num_people;
	uint32_t owner_ix;
}

struct connected_client clients[MAX_CLIENTS];
struct chatroom rooms[MAX_CHATROOMS];


/* Linux Sockets API related globals. */

int	port = SERVER_PORT
   ,listening_socket
   ,optval1 = 1
   ,optval2 = 2
   ,client_socket_fd;
   
	   
socklen_t clientLen = sizeof(struct sockaddr_in);

struct sockaddr_in client_address;
struct sockaddr_in server_address;

/* First thing done when we start the server - initialize it. */
uint32_t self_init(){
	   
    server_address = {  .sin_family = AF_INET
	                   ,.sin_port = htons(port)
	                   ,.sin_addr.s_addr = INADDR_ANY
	                 };
	                                             
	if( (listening_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1){
	    printf("[ERR] Server: Could not open server socket. Aborting.\n");
	    return 1;
	}
	
	setsockopt(
		  listening_socket, SOL_SOCKET, SO_REUSEPORT, &optval1, sizeof(optval1)
	);	
	setsockopt(
	      listening_socket, SOL_SOCKET, SO_REUSEADDR, &optval2, sizeof(optval2)
	);
	                  
	if( 
	   (
	    bind(
	        listening_socket
	       ,(struct sockaddr*)&server_address
	       ,sizeof(server_address)
	    )
	   ) == -1
	  )
	  {
		if(errno != 13){
			printf("[ERR] Server: bind() failed. Errno != 13. Aborting.\n");
			return 1;
		}
	  }
	   
	if( (listen(listening_socket, MAX_SOCK_QUEUE)) == -1){
		printf("[ERR] Server: couldn't begin listening. Aborting.\n");
	    return 1;
	}
	
	
	/*  Server will use its private key to compute Schnorr signatures of 
	 *  everything it transmits, so all users can verify it with the server's
	 *  public key they already have by default for authenticity.
	 */
	FILE* privkey_dat = fopen("server_privkey.dat", "r");
	
	if(!privkey_dat){
		printf("[ERR] Server: couldn't open private key DAT file. Aborting.\n");
		return 1;
	}
	
	if(fread(server_privkey, 1, PRIVKEY_BYTES, privkey_dat) != PRIVKEY_BYTES){
		printf("[ERR] Server: couldn't get private key from file. Aborting.\n");
		return 1;
	}
	else{
		printf("[OK] Server: Successfully loaded private key.\n");
	}
	
	fclose(privkey_dat);
	
	return 0;
}

uint32_t process_new_message(){

	uint8_t* client_message_buf = malloc(MAX_MSG_LEN);
	int64_t  bytes_read; 
	uint64_t transmission_type;
	uint64_t expected_siz;
	
	/* Capture the message the Rosetta TCP client sent to us. */
	bytes_read = recv(client_socket, client_message_buf, MAX_MSG_LEN, 0);
	
	if(bytes_read == -1 || bytes_read < 8){
		printf("[ERR] Server: Couldn't read message on socket or too short.\n");
		return 1;
	}
	else{
		printf( "[OK] Server: Just read %u bytes from a received message!\n\n"
		       ,bytes_read
		);
	}
	
	/* Examine the message and react to it accordingly. */
	
	/* A clear definition of possible TCP messages is needed. Examples:
	 *
	 * - a user sent a text message in their chatroom
	 * - a user's client polled us for any pending messages for them.
	 * - a user wants to create their own new chatroom
	 * - a user wants to enter an existing chatroom
	 * - a user wants to leave a chatroom they're NOT the owner of. 
	 * - a user wants to leave a chatroom which they're the owner of. 
	 * - a user simply initialized connection with the TCP server.
	 *
	 */
	 
	/* Read the first 8 bytes to see what type of transmission it is. */
	transmission_type = *((uint64_t*)client_message_buf);
	
	switch(transmission_type){
	case(MAGIC_0){
	
		/* Size must be in bytes: 8 + 8 + pubkeysiz, which is bytes[8-15] */
		expected_siz = (16 + (*((uint64_t*)(client_message_buf + 8))));
		
		if(bytes_read != expected_siz){
			printf("[WARN] Server: MSG Type was 0 but of wrong size.\n");
			printf("               Size was: %ld\n", bytes_read);
			printf("               Expected: %lu\n", expected_siz);
			printf("\n[OK] Discarding the transmission.\n\n ");
			return 1;
		}
		
		/* Create the new user structure instance with the public key. */
		
		/* A message arrived to permit a newly arrived user to use Rosetta, but
		 * currently the maximum number of clients are using it. Try later.
		 */
		if(next_free_user_ix == MAX_CLIENTS){
			printf("[WARN] - Not enough client slots to let a user in.\n");
			printf("         Letting the user know and to try later.  \n");
			
			/* Let the user know that Rosetta is full right now, try later. */
			if(send(client_socket, "Rosetta is full, try later", 26, 0) == -1){
	            printf("[ERR] Server: Couldn't send full-rosetta message.\n");
	            return 1;
	        }
	        
	        printf("[OK] Server: Told the client Rosetta is full, try later\n");
	        return 0;
		}
		
		clients[next_free_user_ix].room_ix = 0;
		clients[next_free_user_ix].num_pending_msgs = 0;

			
		for(size_t i = 0; i < MAX_PEND_MSGS; ++i){
			clients[next_free_user_ix].pending_msgs[i] = calloc(1, MAX_MSG_LEN);
		}
		
		clients[next_free_user_ix].pubkey_siz_bytes 
		 = (*((uint64_t*)(client_message_buf + 8)));
	
	
		clients[next_free_user_ix].client_pubkey 
		 = 
		 calloc(1, clients[next_free_user_ix].pubkey_siz_bytes);
		 
		memcpy(  clients[next_free_user_ix].client_pubkey 
		 	    ,(client_message_buf + 16)
		 	    ,clients[next_free_user_ix].pubkey_siz_bytes
		 	  );
		
		/* Reflect the new taken user slot in the global user status bitmask. */
		clients_status_bitmask |= (1ULL << (64ULL - next_free_user_ix));
		
		/* Increment it one space to the right, since we're guaranteeing by
		 * logic in the user erause algorithm that we're always filling in
		 * a new user in the leftmost possible empty slot.
		 *
		 * If you're less than (max_users), look at this slot and to the right
		 * in the bitmask for the next leftmost empty user slot index. If you're
		 * equal to (max_users) then the maximum number of users are currently
		 * using Rosetta. Can't let any more people in until one leaves.
		 *
		 * Here you either reach MAX_CLIENTS, which on the next attempt to 
		 * let a user in and fill out a user struct for them, will indicate
		 * that the maximum number of people are currently using Rosetta, or
		 * you reach a bit at an index less than MAX_CLIENTS that is 0 in the
		 * global user slots status bitmask.
		 */
		++next_free_user_ix;
		
		while(next_free_user_ix < MAX_CLIENTS){
			if(!(clients_status_bitmask & (1ULL<<(64ULL - next_free_user_ix))))
			{
				break;
			}
			++next_free_user_ix;
		}
		
		printf("\n[OK] Successfully permitted a new user in Rosetta!\n\n");
		
		return 0;

	}
	
	case(MAGIC_1){
	
	}
	
	} /* end switch */


int main(){
	
	/* Initialize Sockets API, load own private key. */ 
	self_init();

	uint32_t status;
	
	while(1){
	
		/* Block on this accept() call until someone sends us a message. */
		client_socket_fd = accept(  server_socket
			       				   ,(struct sockaddr*)(&client_address)
			       			       ,&clientLen
			      			     );
			      			     
		/* 0 on success, greater than 0 otherwise. */	      			   
		status = process_new_message();
		
		if(status){
			printf("\n\n****** WARNING ******\n\n"
				   "Error while processing a received "
				   "transmission, look at log to find it.\n"
				  );	
		}
			      			
	}
		        

	/* Does it really matter to free() it? Not like the heap space is gonna
	 * be used for anything else at this point, as the server is about to
	 * be shut down. Do it anyway for completeness.
	 */
	 
	free(client_message);
	
}
