/******************************************************************************/

#include "../client/network-code/client-primary-functions.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>

uint8_t make_new_test_acc(void)
{
    struct termios original_terminal_settings;
    struct termios password_terminal_settings;
    unsigned char  savefilename[16] = {'\0'};
    unsigned char* full_save_dir;
    uint8_t        status = 0;
    uint8_t        pw_buf[16] = {0};
    const char*    savedir = "./test-accounts/";
    printf("Creating a new test user account.\n\n");
    printf("Pick a save file name: ");
    scanf("%s", savefilename);
    printf("strlen(filename) = %lu | strlen(savedir) = %lu\n",
           strlen((const char*)savefilename), strlen(savedir));
    full_save_dir =
      calloc(1, strlen(savedir) + strlen((const char*)savefilename));
    memcpy(full_save_dir, savedir, strlen(savedir));
    memcpy(full_save_dir + strlen(savedir), savefilename,
           strlen((const char*)savefilename));

    /* Make terminal input invisible to enter a password. Then bring it back. */
    tcgetattr(STDIN_FILENO, &password_terminal_settings);
    original_terminal_settings = password_terminal_settings;
    password_terminal_settings.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &password_terminal_settings);

    printf("Enter a password up to 15 characters: ");
    /* Read a string of UP TO 15 characters. No more. */
    scanf("%15s", (char*)pw_buf);
    tcsetattr(STDIN_FILENO, TCSANOW, &original_terminal_settings);

    /* The call to reg */
    printf("Entered password: %s\n", (char*)pw_buf);
    status = reg(pw_buf, strlen((char*)pw_buf), (char*)full_save_dir);
    if(status){
        printf("\n[ERR] RTF: reg() failed in make_new_test_acc().\n\n");
        status = 1;
    }

    free(full_save_dir);
    return status;
}

uint8_t spawn_new_test_user(void)
{
    char   buf_savefile_name_password[4 * SMALL_FIELD_LEN];
    char   chr_read;
    char   input_savename[2 * SMALL_FIELD_LEN];
    char   input_password[2 * SMALL_FIELD_LEN];
    char  user_spawner_program_name[] =
      "./src/rosetta-test-framework/user-spawner\0";
    size_t read_input_field_len;
    size_t buffer_second_part_ix;
    pid_t  pid;
    char*  args[4];
    char*  env[] = {NULL};

label_try_again:
    memset(buf_savefile_name_password, 0x00, 4 * SMALL_FIELD_LEN);
    memset(input_savename, 0x00, 2 * SMALL_FIELD_LEN);
    memset(input_password, 0x00, 2 * SMALL_FIELD_LEN);
    printf("Starting a new test user session - Login.\n");
    printf("Enter /-separated saved user filename and password to login.\n"
           "Each 5 to 15 characters long. Example: kevin/123123\n");
    scanf("%31s", buf_savefile_name_password);
    /* Parse the input string. Look for the / separator. Get savename here. */
    read_input_field_len = 0;
    buffer_second_part_ix = 0;
    for(size_t i = 0; i < 4 * SMALL_FIELD_LEN; ++i){
        chr_read = buf_savefile_name_password[i];
        ++read_input_field_len;
        ++buffer_second_part_ix;
        if(chr_read == '/'){
            if(read_input_field_len < 5 || read_input_field_len > 15){
                printf("Try again, 5 to 15 characters each.\n");
                goto label_try_again;
            }
            else{
                break;
            }
        }
        if(chr_read == '\0'){
            printf("Password not found. Try again, 5 to 15 characters each.\n");
            goto label_try_again;
        }
        input_savename[i] = chr_read;
    }
    /* Now grab the entered password too into its own character buffer. */
    read_input_field_len = 0;
    for(size_t i = 0; i < 4 * SMALL_FIELD_LEN; ++i){
        chr_read = buf_savefile_name_password[buffer_second_part_ix++];
        ++read_input_field_len;
        if(chr_read == '\0'){
            if(read_input_field_len < 5 || read_input_field_len > 15){
                printf("Try again, 5 to 15 characters each.\n");
                goto label_try_again;
            }
            else{
                break;
            }
        }
        input_password[i] = chr_read;
    }

    /* We have the entered savename and password. Spawn a user from them.
     * Do that by calling fork() and execve() on the UserSpawner program.
     * execve() expects args[] to be a null-terminated array of pointers to
     * to null-terminated strings.
     */
    pid = fork();
    if(pid < 0){
        perror("Rosetta Test Framework: fork() for User Spawner failed:");
        return 1;
    }
    if(pid > 0){
        printf("Rosetta Test Framework: User process spawned. PID: %d\n", pid);
        return 0;
    }
    else{
        printf("User Spawner: Test user process created.\n"
               "Starting user-spawner program with execve() now.\n"
               "The test user will automatically attempt a login.\n");

        args[0] = (char*)user_spawner_program_name;
        args[1] = input_savename;
        args[2] = input_password;
        args[3] = NULL;

        execve("./src/rosetta-test-framework/user-spawner", args, env);

        /* If execve returns at all, it means it has failed. */
        perror("User Spawner: execve() failed: ");
        return 1;
    }
    return 0;
}

void draw_menu_0()
{
    int bytes;
    FILE* logo_file = fopen("./src/rosetta-test-framework/rtf-logo.txt", "r");
    unsigned char* logo_buf;
    unsigned int op_number;
    uint8_t status = 0;

    /* ========================= PART 1: Draw logo ========================== */

    fseek(logo_file, 0, SEEK_END);
    bytes = ftell(logo_file);
    rewind(logo_file);
    logo_buf = calloc(1, bytes + 1);
    fread(logo_buf, 1, bytes, logo_file);
    logo_buf[bytes] = '\0';
    printf("\n\n\n\n%s\n\n\n\n", logo_buf);

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
    if(op_number == 1){
        status = make_new_test_acc();
        if(status){
            printf("[ERR] RTF: Making a test account fails. Check errors.\n\n");
        }
        else{
            printf("[OK] RTF: Created a new test account!\n\n");
        }
    }
    else if(op_number == 2){
        status = spawn_new_test_user();
    }
    else if(op_number == 3){
        printf("Stopping a test user chat session (logout).\n\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 4){
        printf("Deleting a test user account.\n\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 5){
        printf("Starting the Rosetta server with AF_UNIX communications.\n\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 6){
        printf("Stopping the Rosetta server.\n\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 7){
        printf("Closing all testing and exiting Rosetta Test Framework.\n\n");
        goto label_cleanup;
    }
    else{
        printf("\n< %u is not a supported operation number. Try again...\n\n",
               op_number);
    }
    goto label_again;

label_cleanup:
    free(logo_buf);
    fclose(logo_file);
    return;
}

int main()
{
    draw_menu_0();
    return 0;
}
