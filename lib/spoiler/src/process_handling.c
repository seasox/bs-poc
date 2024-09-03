#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../include/misc.h"

pid_t launch_process(const char *path) {
    pid_t pid = fork(); // Create a new process

    if (pid == -1) {
        // Fork failed
        perror("fork");
        return -1;
    } else if (pid == 0) {
        // This is the child process
        
        // Get the current CPU core
        int core = get_current_cpu_core();
        if (core >= 0) {
            cpu_set_t set;
            CPU_ZERO(&set); // Clear the cpu mask
            CPU_SET(core, &set); // Set the current CPU core in the mask

            // Apply the CPU mask to the current process (the child)
            if (sched_setaffinity(0, sizeof(cpu_set_t), &set) == -1) {
                perror("sched_setaffinity");
                exit(EXIT_FAILURE);
            }
        }

        execl(path, path, (char *)NULL); // Replace the child process with the new process image
        // If execl returns, it means it failed
        perror("execl");
        exit(EXIT_FAILURE);
    }

    // This is the parent process, with 'pid' being the PID of the child (the launched process)
    return pid;
}