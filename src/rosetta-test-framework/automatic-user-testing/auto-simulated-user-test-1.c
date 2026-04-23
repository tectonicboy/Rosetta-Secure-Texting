#include "../../client/network-code/client-primary-functions.h"

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
    printf("[OK]  RTF: Inside Simulation 1 now. Spawning auto-users.\n");
    run_auto_spawner_program(1);
    return 0;
}
