/* Some common file extensions abbreviated. */
#define icotype  "image/x-icon"
#define svgtype  "image/svg+xml"
#define htmltype "text/html"
#define pngtype  "image/png"
#define jpgtype  "image/jpg"
#define csstype  "text/css"
#define jstype   "text/javascript"
#define aviftype "image/avif"

/* Represent each file as a structure. */
struct site_file{
	char* fname;
	char* ftype;
	char* fmode;
	char* fbuf;	
	uint32_t fsize;
};

size_t ReadFile(char* filePath, char** buffer, char* mode) {

    FILE *fd = fopen(filePath, mode);
    	
    uint32_t numBytes, read;
    	
    if (!fd) {
       	printf("[ERR] Library: Could not open file: %s\n", filePath);
       	return 0;
   	}
    	
    /* Set position indicator at EOF */
    if( fseek(fd, 0, SEEK_END) == -1 ){
   	    printf("[ERR] Library: fseek() failed at line: %d\n", __LINE__);
   	    return 0;
   	}
   	
   	/* Get current position indicator -- get file size */
   	if( (numBytes = ftell(fd)) == -1 ){
   	    printf("[ERR] Library: ftell() failed at line: %d\n", __LINE__);
   	    return 0; 
   	};
   	
   	/* Set position indicator back at start */
   	if( fseek(fd, 0, SEEK_SET) == -1 ){
   	    printf("[ERR] Library: fseek() failed at line: %d\n", __LINE__);
   	    return 0;
   	} 
   	    
   	printf("[OK] Library: File size of %s obtained: %u\n", filePath, numBytes);
   	
   	if (!numBytes) {
       	fclose(fd);
       	printf("[ERR] Library: File is empty: %s\n", filePath);
       	return 0;
    }
    
    if( ! (*buffer = calloc(1, numBytes)) ){
        printf("[ERR] Library: Memory error. LINE: %d\n", __LINE__);
        return 0;
    }

    if( ! (read = fread(*buffer, numBytes, 1, fd)) ){
        printf("[ERR] Library: fread() had an error or read 0 bytes from opened file. Exiting.\n");
        exit(1);
    }

    	
   	printf("[OK] Library: read file %s successfully.\n", filePath);
    	
    fclose(fd);

    return numBytes;
}

uint32_t Create_HTTPsend_Filebuf(char* fname, char* ftype, char* mode, char** buf){

    char  *http_header = "HTTP/1.1 200 OK\n\rContent-Type: "
         ,*cont_len = "Content-Length: "
         ,*fbuf
         ,*fullHeader;
         
    size_t fsiz = ReadFile(fname, &fbuf, mode);
    uint32_t bufsiz;
    
    int bytes_put;
    
   	bytes_put = asprintf(&fullHeader, "%s %s\r\n%s %lu\r\n\n", http_header, ftype, cont_len, fsiz);
   	
   	if(!bytes_put){
   	    printf("[ERR] Library: asprintf() had an error or wrote 0 bytes to fullHeader. Exiting.\n");
   	    exit(1);
   	}
   	
    *buf = calloc(1, (strlen(fullHeader) + fsiz));
    
    memcpy(*buf, fullHeader, strlen(fullHeader));
    memcpy(*buf + strlen(fullHeader), fbuf, fsiz);
    
	bufsiz = strlen(fullHeader) + fsiz;
	
    free(fullHeader);
	return bufsiz;
}



uint64_t find_substr(
    char* str, char* substr, uint64_t pos, uint64_t max_i, size_t strsiz
)                    
{
	uint64_t  smallsiz = strlen(substr)
	         ,siz1     = (max_i - smallsiz)
	         ,siz2     = (strsiz - smallsiz)
	         ,i
	         ,j
	         ;
	         
	char flags = 0;
	
	for(i = pos; i <= siz1 && i < siz2; ++i){
		flags |= 1;
		for(j = 0; j < smallsiz; ++j){
			if(str[i+j] != substr[j]){
				flags &= (~1); 
				break;
			}
		}
		if(flags & 1){ return i; }
	}	
	
	return max_i;
}




long long hexdec(char first, char second){
	char hex[3];
	long long decimal;
	int i = 0, val = 0, len;

	decimal = 0;

	hex[0] = first; hex[1] = second; hex[2] = '\0';

	len = strlen(hex);
	len--;

	for(i=0; hex[i]!='\0'; i++){
		if(hex[i]>='0' && hex[i]<='9'){
			val = hex[i] - 48;
		}
		else if(hex[i]>='a' && hex[i]<='f'){
			val = hex[i] - 97 + 10;
		}
		else if(hex[i]>='A' && hex[i]<='F'){
			val = hex[i] - 65 + 10;
		}
		decimal += (val << (len << 2));
		len--;
	}
	return decimal;
}




unsigned Extract_HTTP_Variables(char* client_msg, char* serv_vars){

	signed int counter = 0, found = 0;
    unsigned int i = 0, j = 0, offset = 0;
    
    while(
           (i < 2048) 
           && 
           !(
                 (client_msg[i]   == 'a') 
              && (client_msg[i+1] == 'c') 
              && (client_msg[i+2] == 't')
	          && (client_msg[i+3] == 'i') 
	          && (client_msg[i+4] == 'o') 
	          && (client_msg[i+5] == 'n') 
	          && (client_msg[i+6] == '=')
	        )
	     )
    {
    	++i;
    }
    
	if(i < 2048){ 
	    /*printf("[OK] Library: Server variables found.\n"); */
	    found = 1;
	}
	
    else {
        /*printf("[OK] Library: No server variables found.\n"); */
    }
    
	if(found){
	    for(j = i; client_msg[j] != '\0';){
			while(client_msg[j] != '='){
			    ++j; 
			    ++counter; 
			    ++offset;
			}
			++j; 
			++counter; 
			++offset;
			while(client_msg[j] != '&'){
				if((client_msg[j] == '%')){
	    			serv_vars[j - i - offset] = hexdec(client_msg[j+1], client_msg[j+2]);
	    			j += 3;
					offset += 2;
					++counter;
	    		}
		    	else{
		    		serv_vars[j - i - offset] = client_msg[j];
		    		++j; 
				    ++counter;
		    	}
				if(client_msg[j] == '\0'){
					/*printf("[OK] Library: Extracted HTTP variables: %s\n", serv_vars);*/
					return i;
				}
			}
			serv_vars[j - i - offset] = '-';
			++j; 
			++counter;
	    }
	}
	return i;
}




