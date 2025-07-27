#include "../client/network-code/client-primary-functions.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/******************************************************************************/


void make_new_test_acc(uint8_t* pw, uint8_t pw_len, char* save_dir){

    uint8_t result = reg(pw, pw_len, save_dir);
    //uint8_t result = 0;
    if(result){
        printf("[ERR] RTF: Test account creation failed.\n");
    }
    else{
        printf("[OK] RTF: Test account has been created at: %s\n", save_dir); 
    }

    return;
}

void draw_menu_0(){

    int bytes;
    FILE* logo_file = fopen("rtf-logo.txt", "r");
    unsigned char* logo_buf;    
    unsigned int   op_number;

    /* ========================= PART 1: Draw logo ========================== */

    fseek(logo_file, 0, SEEK_END);  

    bytes = ftell(logo_file);

    rewind(logo_file);

    logo_buf = calloc(1, bytes + 1);

    fread(logo_buf, 1, bytes, logo_file);

    logo_buf[bytes] = '\0';

    printf("\n\n\n%s\n\n\n\n\n\n\n\n\n\n", logo_buf);

    /* ====================== PART 2: Top menu options ====================== */

    printf("The following control console operations are supported by RTF.\n");
    printf("Enter an option number to perform its test operation.\n\n\n");

    printf(
     "#========#============================================================#\n"
     "| OPTION | Operation performed                                        |\n"
     "#========#============================================================#\n"
     "|      1 | Create a new test user account at a custom directory.      |\n"
     "|      2 | Start a test user chat session (login).                    |\n"
     "|      3 | Stop  a test user chat session (logout)                    |\n"
     "|      4 | Delete a test user account.                                |\n"
     "|      5 | Start the Rosetta server OS process, for AF_UNIX ipc.      |\n"
     "|      6 | Stop  the Rosetta server.                                  |\n"
     "|      7 | Close all testing and exit RTF.                            |\n"
     "#========#============================================================#\n"
     "\n"
    );

label_again:

    printf("\nEnter next operation: ");

    scanf("%u", &op_number);

    printf("\n\nOperation selected: ");

    if(op_number == 1){
        printf("Creating a new test user account.\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 2){
        printf("Starting a test user chat session (login).\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 3){
        printf("Stopping a test user chat session (logout).\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 4){
        printf("Deleting a test user account.\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 5){
        printf("Starting the Rosetta server with AF_UNIX communications.\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 6){
        printf("Stopping the Rosetta server.\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 7){
        printf("Closing all testing and exiting Rosetta Test Framework.\n");
        goto label_cleanup;
    }
    else{
        printf( "\n< %u is not a supported operation number. Try again...\n\n"
               ,op_number
        );
    }

    goto label_again;

label_cleanup:

    free(logo_buf);
    fclose(logo_file);
 
    return;
}

int main(){

    draw_menu_0();

    return 0;
}
