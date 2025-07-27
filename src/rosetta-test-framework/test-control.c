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

    fseek(logo_file, 0, SEEK_END);  

    bytes = ftell(logo_file);

    rewind(logo_file);

    logo_buf = calloc(1, bytes + 1);

    fread(logo_buf, 1, bytes, logo_file);

    logo_buf[bytes] = '\0';

    printf("\n\n\n%s\n\n\n", logo_buf);

    free(logo_buf);
    fclose(logo_file);
 
    return;
}

int main(){

    draw_menu_0();

}
