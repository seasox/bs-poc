//Importing standard library
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <time.h>
#include <sched.h>
#include<unistd.h>

void main(){
    uint64_t x = 0xDEADBEEF;
    // Create a target that is 8kb in size
    uint8_t *target[8192];
    // Fill target with zeros
    for (int i = 0; i < 8192; i++) {
        target[i] = 0;
    }
    // sleep for 2 seconds
    sleep(2);
    // iterate through the target to see which addresses flipped
    for (int i = 0; i < 8192; i++) {
        if(target[i] != 0){
            // log it to a file
            FILE *file = fopen("flipped.txt", "a+");
            fprintf(file, "Byte %d flipped\n", i);
        }
    }
}