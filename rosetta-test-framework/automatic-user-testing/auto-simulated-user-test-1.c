#include "../../src/client/network-code/client-primary-functions.h"

#define NUMBER_OF_AUTO_USERS 3

void start_rosetta_server(void){
    char* args[3] = {ROSETTA_SERVER_PROG_PATH, "1", NULL};
    char* env[] = {NULL};
    pid_t pid = fork();
    if(pid < 0){
        printf("[ERR] RTF Simulation 1: fork for rosetta-server failed.");
        exit(1);
    }
    else if(pid > 0){
        printf("[OK]  RTF Simulation 1: rosetta-server process spawned!\n");
    }
    else{
        printf("[OK]  RTF Simulation 1: Inside child process.    \n"
               "                        Launching rosetta-server.\n");
        execve(ROSETTA_SERVER_PROG_PATH, args, env);
        /* Here, if execve() returns at all, it means it has failed. */
        printf("[ERR] RTF Simulation 1: execve failed for rosetta-server\n.");
        exit(1);
    }
}

void run_auto_spawner_program(uint64_t spawner_num){
    pid_t pid;
		int n;
		char* args[2];
		char* env[] = {NULL};
    char full_auto_spawner_prog_path[1024];
		memset(full_auto_spawner_prog_path, 0x00, 1024);
		const char* base_auto_spawner_prog_path =
			AUTOMATIC_USER_SIMULATION_AUTO_SPAWNER_BASE_PATH;
		u64 base_auto_spawner_prog_path_len = strlen(base_auto_spawner_prog_path);
		strncpy(full_auto_spawner_prog_path, base_auto_spawner_prog_path,
						base_auto_spawner_prog_path_len);
		n = sprintf(full_auto_spawner_prog_path + base_auto_spawner_prog_path_len,
							  "%lu", spawner_num);
		if(!n){
        printf("[ERR] RTF Simulation 1: Failed to obtain full path to\n"
							 "                        program auto-spawner1\n");
	      exit(1);
		}
    pid = fork();
		if(pid < 0){
        printf("[ERR] RTF Simulation 1: fork failed, user: %lu\n", spawner_num);
				exit(1);
		}
		else if(pid > 0){
        printf("[OK]  RTF Simulation 1: auto-user %lu process spawned!\n",
							 spawner_num);
		}
		else{
        printf("[OK]  RTF Simulation 1: Inside child process.       \n"
							 "                        Executing auto-user program. Path:\n");
				printf("%s\n", full_auto_spawner_prog_path);
				args[0] = (char*)full_auto_spawner_prog_path;
				args[1] = NULL;
				execve(full_auto_spawner_prog_path, args, env);
				/* Here, if execve() returns at all, it means it has failed. */
				printf("[ERR] RTF Simulation 1: execve() failed for an auto-spawner.");
				exit(1);
		}
}

int main(){
		uint64_t runs_completed = 0;
		uint64_t runs_needed = 128;
		printf("[OK]  RTF: Inside simulation 1. Reset STABILIZED_AVERAGES.dat\n");
		FILE* stabilized_averages_dat_fd =fopen("/home/hypervisor123/tmp/repos/Rosetta-Secure-Texting/performance-analysis/latest-stabilized-averages.dat", "w");
		if(stabilized_averages_dat_fd == NULL){
        printf("[ERR] RTF: Simulation 1: STABILIZED_AVERAGES failed to open\n");
				exit(1);
		}
		fclose(stabilized_averages_dat_fd);
		//printf("[OK]  RTF: Inside Simulation 1. Starting Rosetta server.\n");
		//start_rosetta_server();
		//sleep(2);
    printf("[OK]  RTF: Inside Simulation 1. Spawning auto-users.\n");
label_again:
		for(size_t i = 1; i <= NUMBER_OF_AUTO_USERS; ++i){
        run_auto_spawner_program(i);
        sleep(3);
	  }
		/* ?? OUTDATED ?? Total sleep after spawning last user: 24 seconds.*/
		/* ?? OUTDATED ?? Total simulation runtime: 30 seconds. */
		sleep(25);
		printf("\n\nSIMULATION 1 ----> Call python to analyze measurements.");
		printf("\n\nSIMULATION 1 ----> USING: NON-Interleaved, new inner loop.\n\n");
		system("PYTHONPATH=/home/hypervisor123/.local/lib/python3.14/site-packages python3 /home/hypervisor123/tmp/repos/Rosetta-Secure-Texting/performance-analysis/process-measurements.py");
		sleep(0.3);
		if(++runs_completed < runs_needed){
        printf("\n\n\n----------->   START SIMULATION RUN: %lu   <-----------\n\n\n", runs_completed);
        goto label_again;
		}
		printf("[OK] Simulation 1 test completed! Closing now...\n");
    return 0;
}
