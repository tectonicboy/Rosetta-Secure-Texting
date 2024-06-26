#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cryptolib.h"
#include "bigint.h"

#define SERVER_PORT 54746;

int	port = SERVER_PORT
   ,listening_socket
   ,optval1 = 1
   ,optval2 = 2
   ,client_socket_fd;
   
	   
socklen_t clientLen = sizeof(struct sockaddr_in);

struct sockaddr_in client_address;
struct sockaddr_in server_address;

void self_init(){
	   
    server_address = {  .sin_family = AF_INET
	                   ,.sin_port = htons(port)
	                   ,.sin_addr.s_addr = INADDR_ANY
	                 };
	                                             
	if( (listening_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1){
	    printf("[ERR] Server: Could not open server socket. Aborting.\n");
	    return 1;
	}
	
	setsockopt(
		  listening_socket
		, SOL_SOCKET
		, SO_REUSEPORT
		, &optval1
		, sizeof(optval1)
	);
		
	setsockopt(
	      listening_socket
		, SOL_SOCKET
		, SO_REUSEADDR
		, &optval2
		, sizeof(optval2)
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
	   
	if( (listen(listening_socket, 1024)) == -1){
		printf("[ERR] Server: Critical - could not begin listening. Aborting.\n");
	    return 1;
	}
	
	/* DONT FORGET TO ADD CODE FOR READING IN THE SERVER'S PRIVATE KEY!!! */
	/* IT SHOULD ALSO BE PASSWORD-ENCRYPTED WITH ARGON2 !!! 		      */
}

uint32_t process_new_message(){

	size_t  client_msg_max_len = 4096;
	char*   client_message_buf = malloc(client_msg_max_len);
	int64_t bytes_read; 
	
	/* Capture the message the Rosetta TCP client sent to us. */
	if((bytes_read = recv(client_socket, client_message_buf, 4096, 0)) == -1){
		printf("[ERR] Server: Couldn't read message on client socket.\n");
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
	 * - a user wants to create their own new chatroom
	 * - a user wants to enter an existing chatroom
	 * - a user wants to leave a chatroom they're NOT the owner of. 
	 * - a user wants to leave a chatroom which they're the owner of. 
	 * - a user simply initialized connection with the TCP server.
	 *
	 */
}

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
			printf("*** WARNING ***\n\n"
				   "Error while processing a received "
				   "message, look at log to find it.\n"
				  );	
		}
			      			
	}
		        

	/* Does it really matter to free() it? Not like the heap space is gonna
	 * be used for anything else at this point, as the server is about to
	 * be shut down. Do it anyway for completeness.
	 */
	 
	free(client_message);
	
}
