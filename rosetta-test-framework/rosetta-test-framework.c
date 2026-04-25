#include "../src/client/network-code/client-primary-functions.h"
#include <termios.h>

uint8_t make_new_test_acc(void)
{
    struct termios original_terminal_settings;
    struct termios password_terminal_settings;
    unsigned char  savefilename[16] = {'\0'};
    unsigned char* full_save_dir;
    uint8_t        status = 0;
    uint8_t        pw_buf[16] = {0};
    const char*    savedir = USER_SAVEFILES_DIR;

    printf("Creating a new test user account.\n\n");
    printf("Pick a save file name: ");
    scanf("%15s", savefilename);
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

uint8_t start_automatic_user_simulation_test(uint64_t test_num)
{
    pid_t pid;
    char* args[2];
    char* env[] = {NULL};
    char full_test_prog_path[1024];
		memset(full_test_prog_path, 0x00, 1024);
    const char* base_test_prog_path =
			AUTOMATIC_USER_SIMULATION_TEST_PROG_BASE_PATH;
		size_t base_test_prog_path_len = strlen(base_test_prog_path);
    strncpy(full_test_prog_path, base_test_prog_path, base_test_prog_path_len);
    int n = sprintf
			        (full_test_prog_path + base_test_prog_path_len, "%lu", test_num);
    if(!n){
        printf("[ERR] RTF: Failed to obtain full simulation test path.\n");
				return 1;
		}
    printf("Starting an automatic test of the whole system.\n");
    /* Run an automatic test program, which spawns Rosetta users simulated by
		 * local OS processes talking over inter-process communication sockets.
     * Call fork() and execve() with the selected automatic test program.
		 * execve() expects args[] to be a null-terminated array of pointers to
     * null-terminated strings.
     */
    pid = fork();
    if(pid < 0){
        perror("[ERR] RTF: fork() for User Spawner failed:");
        return 1;
    }
		else if(pid > 0){
        printf("[OK]  RTF: Child process spawned. PID: %d\n", pid);
        return 0;
    }
    else{
        printf("[OK]  RTF: Inside child process now. Starting test...\n");
				args[0] = (char*)full_test_prog_path;
        args[1] = NULL;
				printf("[OK]  RTF: Child process: calling execve() on path:\n%s\n",
							 full_test_prog_path);
        execve(full_test_prog_path, args, env);
        /* If execve returns at all, it means it has failed. */
        perror("[ERR] RTF: Child process: execve() failed: ");
        return 1;
    }
    return 0;
}

void draw_menu_0()
{
    int logo_file_size;
    FILE* logo_file = fopen(RTF_LOGO_PATH, "r");
    unsigned char* logo_buf;
    unsigned int op_number;
		uint64_t test_number;
    uint8_t status = 0;

    /* ========================= PART 1: Draw logo ========================== */

    fseek(logo_file, 0, SEEK_END);
    logo_file_size = ftell(logo_file);
    rewind(logo_file);
    logo_buf = calloc(1, logo_file_size + 1);
    fread(logo_buf, 1, logo_file_size, logo_file);
    logo_buf[logo_file_size] = '\0';
    printf("\n\n%s\n\n\n\n", logo_buf);

    /* ====================== PART 2: Top menu options ====================== */

    printf(
"#========#=================================================================#\n"
"| OPTION | Operation performed                                             |\n"
"#========#=================================================================#\n"
"|      1 | Create a new encrypted user account savefile for testing.       |\n"
"|      2 | Delete a test user account.                                     |\n"
"|      3 | Run one of the automatic user simulation whole-system tests.    |\n"
"|      4 | Start the Rosetta server with local interprocess communication. |\n"
"|      5 | Stop the Rosetta server.                                        |\n"
"|      6 | Exit the test framework.                                        |\n"
"#========#=================================================================#\n"
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
            printf("[OK]  RTF: Created a new test account!\n\n");
        }
    }
    else if(op_number == 2){
        printf("Deleting a test user account.\n\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 3){
        printf("Enter the test number to run: ");
        scanf("%lu", &test_number);
        status = start_automatic_user_simulation_test(test_number);
        if(status){
            printf("[ERR] RTF: Something went wrong. Possible errors above.\n");
        }
    }
    else if(op_number == 4){
        printf("Starting the Rosetta server with AF_UNIX communications.\n\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 5){
        printf("Stopping the Rosetta server.\n\n");
        printf("[NOT IMPLEMENTED YET]\n\n");
    }
    else if(op_number == 6){
        printf("Exiting Rosetta Test Framework.\n\n");
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
