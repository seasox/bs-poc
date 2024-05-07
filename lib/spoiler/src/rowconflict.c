#include "../include/misc.h"
#include "../include/spoiler.h"
#include "../include/drama.h"
#include "../include/rowconflict.h"

#include <math.h>

// Test


int ROW_CONLICT_OUTLIER = -1;
int ROW_CONLICT_THRESH = -1;
#define ROW_CONFLICT_TRIALS 1500
#define ROUNDS_TO_FIND_THRESHOLD 1000
#define OUTLIER_STDS 3
#define THRESHOLD_STDS 2


int getRowConflictOutlierThreshold(struct addr_space *continuous_buffer) {
    int rounds = 0;
    // Allocate a buffer large enough to store all measurements
    uint16_t *measurementBuffer = (uint16_t *)malloc(sizeof(uint16_t) * continuous_buffer->length * ROW_CONFLICT_TRIALS);
    if (measurementBuffer == NULL) {
        // Handle memory allocation failure
        return -1; // Indicate failure
    }

    for (int p = 0; p < continuous_buffer->length; p++) {
        uint32_t read_time = 0;
        for (int r = 0; r < ROW_CONFLICT_TRIALS; r++) {
            clfmeasure(continuous_buffer->memory_addresses[0], continuous_buffer->memory_addresses[p], &read_time);
            measurementBuffer[p * ROW_CONFLICT_TRIALS + r] = read_time;
        }
        rounds++;
        if (rounds > ROUNDS_TO_FIND_THRESHOLD) {
            break;
        }
    }

    // Calculate the mean of all read_time values
    double sum = 0;
    int total_measurements = rounds * ROW_CONFLICT_TRIALS;
    for (int i = 0; i < total_measurements; i++) {
        sum += measurementBuffer[i];
    }
    double mean = sum / total_measurements;

    // Calculate the standard deviation
    double variance_sum = 0;
    for (int i = 0; i < total_measurements; i++) {
        variance_sum += pow(measurementBuffer[i] - mean, 2);
    }
    double variance = variance_sum / total_measurements;
    double standard_deviation = sqrt(variance);

    // Determine two standard deviations from the mean
    double outlier_threshold = mean + OUTLIER_STDS * standard_deviation;

    // Clean up allocated memory
    free(measurementBuffer);

    // Since outlier_threshold is a double but the function is expected to return an int,
    // we'll round the threshold to the nearest integer.
    return (int)round(outlier_threshold);
}

int getRowConflictThreshold(struct addr_space *continuous_buffer) {
    int rounds = 0;
    // Allocate a buffer large enough to store all measurements
    uint16_t *measurementBuffer = (uint16_t *)malloc(sizeof(uint16_t) * continuous_buffer->length);
    if (measurementBuffer == NULL) {
        // Handle memory allocation failure
        return -1; // Indicate failure
    }

    int total;
    uint32_t read_time = 0;
    for (int p = 0; p < continuous_buffer->length; p++)
    {
        total = 0;
        int cc = 0;
        for (int r = 0; r < ROW_CONFLICT_TRIALS; r++)
        {
            clfmeasure(continuous_buffer->memory_addresses[0], continuous_buffer->memory_addresses[p], &read_time);
            if (read_time < ROW_CONLICT_OUTLIER)
            {
                total = total + read_time;
                cc++;
            }
        }
        measurementBuffer[p] = total / cc;
    }

    // Calculate the mean of all read_time values
    double sum = 0;
    int total_measurements = continuous_buffer->length;
    for (int i = 0; i < total_measurements; i++) {
        sum += measurementBuffer[i];
    }
    double mean = sum / total_measurements;

    // Calculate the standard deviation
    double variance_sum = 0;
    for (int i = 0; i < total_measurements; i++) {
        variance_sum += pow(measurementBuffer[i] - mean, 2);
    }
    double variance = variance_sum / total_measurements;
    double standard_deviation = sqrt(variance);

    // Determine two standard deviations from the mean
    double outlier_threshold = mean + THRESHOLD_STDS * standard_deviation;

    // Clean up allocated memory
    free(measurementBuffer);

    // Since outlier_threshold is a double but the function is expected to return an int,
    // we'll round the threshold to the nearest integer.
    return (int)round(outlier_threshold);
}


// Method will return continuous memory going into the same bank
struct addr_space *rowconflict(struct addr_space *continuous_buffer)
{

    if(ROW_CONLICT_OUTLIER == -1){
        ROW_CONLICT_OUTLIER = getRowConflictOutlierThreshold(continuous_buffer);
        printf("Row conflict outlier threshold: %d\n", ROW_CONLICT_OUTLIER);
    }
    if(ROW_CONLICT_THRESH == -1){
        ROW_CONLICT_THRESH = getRowConflictThreshold(continuous_buffer);
        printf("Row conflict threshold: %d\n", ROW_CONLICT_THRESH);
    }

    struct addr_space *return_bank = malloc(sizeof(struct addr_space));

    int *conflict = (int *)malloc(sizeof(int) * (continuous_buffer->length));
    uint16_t *measurementBuffer = (uint16_t *)malloc(sizeof(int) * (continuous_buffer->length) * ROW_CONFLICT_TRIALS);

    clock_t cl = clock();

    int conflict_index = 0;
    int total;

    uint32_t tt = 0;
    float timer = 0.0;

    for (int p = 0; p < continuous_buffer->length; p++)
    {
        total = 0;
        int cc = 0;
        for (int r = 0; r < ROW_CONFLICT_TRIALS; r++)
        {
            clfmeasure(continuous_buffer->memory_addresses[0], continuous_buffer->memory_addresses[p], &tt);
            measurementBuffer[p * ROW_CONFLICT_TRIALS + r] = tt;
            if (tt < ROW_CONLICT_OUTLIER)
            {
                total = total + tt;
                cc++;
            }
        }
        if (total / cc > ROW_CONLICT_THRESH)
        {
            conflict[conflict_index] = p;
            conflict_index++;
        }
    }
    cl = clock() - cl;
    timer = ((float)cl) / CLOCKS_PER_SEC;

    // print out the conflict_index
    return_bank->length = conflict_index;

    // Create an array of pointers to the memory addresses that are continuous
    return_bank->memory_addresses = malloc(sizeof(uint8_t *) * (conflict_index * PAGE_SIZE));

    int first_conflict_index = conflict[0];

    int specialBufferIndex = 0;
    for (int h = 0; h < conflict_index; h++)
    {
        return_bank->memory_addresses[specialBufferIndex] = continuous_buffer->memory_addresses[(conflict[h])];
        specialBufferIndex++;
    }
    //log_measurement_buffer(continuous_buffer, measurementBuffer);
    log_rowconflict(return_bank);

    return return_bank;
}

void log_measurement_buffer(struct addr_space *buffer, uint16_t *measurementBuffer)
{
    FILE *file = fopen("memory_profiling/logs/rowconflict_measurement.csv", "w");
    for(int i = 0; i < buffer->length; i++){
        for(int j = 0; j < ROW_CONFLICT_TRIALS; j++){
            fprintf(file, "%lx,%lx,%d\n", 
                (uint64_t)buffer->memory_addresses[i], 
                get_physical_addr((uint64_t)buffer->memory_addresses[i]), 
                measurementBuffer[i*ROW_CONFLICT_TRIALS+j]);
        }
        if(i > 1000){ // File could get too large...
            break;
        }
    }
}

void log_rowconflict(struct addr_space *return_bank)
{
    const char *directory = "memory_profiling";
    const char *filename = "memory_profiling/logs/rowconflict.csv";

    // Check if the directory exists, if not create it
    struct stat st = {0};
    if (stat(directory, &st) == -1)
    {
        if (mkdir(directory, 0700) == -1)
        {
            perror("Error creating directory");
            return;
        }
    }

    // Attempt to open the file, creating it if it doesn't exist
    FILE *bank_file = fopen(filename, "w");
    if (!bank_file)
    {
        perror("Error opening Row Conflict log");
        return;
    }

    // Write the header to the file
    fprintf(bank_file, "vaddr,physaddr,bank,row\n");

    // Loop through the addresses in return_bank and log the details
    for (int i = 0; i < return_bank->length; i++)
    {
        uint64_t phys_addr = get_physical_addr((uint64_t)return_bank->memory_addresses[i]);
        int bank = phys_2_dram(phys_addr).bank;
        int row = phys_2_dram(phys_addr).row;
        fprintf(bank_file, "0x%lx,0x%lx,%d,%d\n", (uint64_t)return_bank->memory_addresses[i], phys_addr, bank, row);
    }

    // If root, change file permissions to make it writable by non-root
    if (getuid() == 0)
    {
        if (chmod(filename, 0664) == -1)
        { // Adjusted permissions to read & write by owner and group, read by others
            perror("Error setting file permissions");
        }
    }

    // Close the file
    fclose(bank_file);
}

void append_row_conflict(const char *filename, uint64_t virt_addr, int MAX_LINE_LENGTH)
{
    // Open the file for reading
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        perror("Error opening Row Conflict log for reading");
        return;
    }

    // Read the entire file content into a string
    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = malloc(fsize + MAX_LINE_LENGTH); // Extra space for modifications
    fread(content, 1, fsize, file);
    fclose(file);

    // Modify the content
    char *ptr = content;
    char line[MAX_LINE_LENGTH];
    while (*ptr)
    {
        sscanf(ptr, "%[^\n]\n", line);
        uint64_t file_virt_addr;
        sscanf(line, "0x%lx", &file_virt_addr);
        if (file_virt_addr == virt_addr)
        {
            strcat(line, " <-- row_conflict");
        }
        strcat(ptr, line);
        ptr += strlen(line);
        if (*ptr)
            ptr++; // Skip the newline character
    }

    // Write the modified content back to the file
    file = fopen(filename, "w");
    if (!file)
    {
        perror("Error opening Row Conflict log for writing");
        free(content);
        return;
    }

    fwrite(content, 1, strlen(content), file);
    fclose(file);
    free(content);
}

int getIndex(uint64_t addr, uint8_t *myBank, int bankLength)
{
    int index = 0;
    for (int i = 0; i < bankLength; i++)
    {
        if ((uint64_t)&myBank[i] == addr)
        {
            index = i;
            break;
        }
    }
    return index;
}

int get_index_of_address(uint64_t current_flippy, struct addr_space *myBank)
{
    for (int i = 0; i < myBank->length; i++)
    {
        if ((uint64_t)myBank->memory_addresses[i] == current_flippy)
        {
            printf("comparing %ld to %ld\n", (uint64_t)myBank->memory_addresses[i], current_flippy);
            return i;
        }
    }
    return -1;
}