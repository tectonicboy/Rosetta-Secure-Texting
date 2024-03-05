/*======================================================*/
/*  The following section handles the initializing of   */
/*  all the files that the web server may potentially   */
/*  be sending over to a web client.                    */      
/*======================================================*/


/* Total number of local files the server knows about.  */
#define SITE_FILES        3
#define MAX_ACTIVE_USERS  64
#define MAX_USER_NAME_SIZ 15
#define MAX_ROOM_NAME_SIZ 15
#define MAX_ROOM_PASS_SIZ 15
#define MAX_ACTIVE_ROOMS  32
#define MAX_MSG_LEN       1023


struct site_file 
            f0 = { .fname = "../Frontend/HTML/index.html"
                  ,.ftype = htmltype 
                  ,.fmode = "r"
                 }
           ,f1 = { .fname = "../../resources/restricted.png"
                  ,.ftype = pngtype
                  ,.fmode = "rb"
                 }
           ,f2 = { .fname = "../../resources/security.png"
                  ,.ftype = pngtype
                  ,.fmode = "rb"
                 }
           ;
           
/*======================================================*/
/*  This is an array of pointers to all the site_file   */
/*  structures that each file the server may send to    */
/*  a web client is stored in.                          */
/*======================================================*/
struct site_file** site_files;


uint8_t init_files(void){
    if(posix_memalign((void*)&site_files, 64, SITE_FILES * sizeof(struct site_file*))){
        printf("[ERR] Server: Memory error on line [%d]\n", __LINE__); 
        return 1;
    }

    site_files[0] = &f0; 
    site_files[1] = &f1; 
    site_files[2] = &f2; 

    
    for(uint8_t i = 0; i < SITE_FILES; ++i){ 
        site_files[i]->fsize = Create_HTTPsend_Filebuf(
                                                       site_files[i]->fname
                                                      ,site_files[i]->ftype
                                                      ,site_files[i]->fmode
                                                      ,&(site_files[i]->fbuf)
                                                      );
    }
    return 0;
}
