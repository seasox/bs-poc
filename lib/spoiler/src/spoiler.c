#include "../include/misc.h"
#include "../include/spoiler.h"
#include "../include/drama.h"

// Include pow library
#include <math.h>
#include <assert.h>

uint64_t *extract_diffBuffer(uint8_t *buffer, uint64_t profile_size, uint64_t *size);
uint64_t sub_abs(uint64_t a, uint64_t b);

// Calculate the inertia of the clusters
uint64_t calculate_inertia(uint64_t *data, int n, int *clusters, int k, int *centers)
{
	uint64_t inertia = 0;
	for (int i = 0; i < n; i++)
	{
		inertia += pow(data[i] - centers[clusters[i]], 2);
	}
	return inertia;
}

uint64_t sub_abs(uint64_t a, uint64_t b)
{
	if (a > b)
	{
		return a - b;
	}
	return b - a;
}

// This is a kmeans function which consumes:
// 1. data: an array of uint64_t values
// 2. n: the number of elements in the data array
// 3. k: the number of clusters to form
// 4. max_iterations: the maximum number of iterations to run the algorithm
// 5. clusters: an array of integers to store the cluster assignments for each data point
uint64_t *kmeans(uint64_t *data, int n, int k, int max_iterations, uint64_t *clusters)
{
	// First initialize the cluster centers, they should be linearly spaced between the min and max values of the data
	uint64_t min = data[0];
	uint64_t max = data[0];
	for (int i = 0; i < n; i++)
	{
		if (data[i] < min)
		{
			min = data[i];
		}
		if (data[i] > max)
		{
			max = data[i];
		}
	}
	uint64_t *centers = (uint64_t *)malloc(k * sizeof(uint64_t));
	// Pick 3 random values to be the initial centers
	centers[0] = data[rand() % n];
	centers[1] = data[rand() % n];
	centers[2] = data[rand() % n];

	// print the initial centers
	printf("Initial Centers: %ld, %ld, %ld\n", centers[0], centers[1], centers[2]);

	// Now we can run the kmeans algorithm
	// Iterate through the max number of iterations
	for (int iteration = 0; iteration < max_iterations; iteration++)
	{
		// Assign each data point to the nearest cluster
		for (int i = 0; i < n; i++)
		{
			uint64_t min_distance = sub_abs(data[i], centers[0]);
			uint64_t distance = min_distance;
			clusters[i] = 0;
			for (int j = 0; j < k; j++)
			{
				distance = sub_abs(data[i], centers[j]);

				if (distance < min_distance)
				{
					min_distance = distance;
					clusters[i] = j;
				}
			}
			// printf("%i, Data: %d, Center: %d, Distance: %f, Cluster: %d\n", i, data[i], min_distance, clusters[i]);
		}
		// recompute the centers
		int *counts = (int *)malloc(k * sizeof(int));
		for (int j = 0; j < k; j++)
		{
			counts[j] = 0;
			centers[j] = 0;
		}
		for (int j = 0; j < n; j++)
		{
			counts[clusters[j]]++;
			centers[clusters[j]] += data[j];
		}
		for (int j = 0; j < k; j++)
		{
			if (counts[j] != 0)
			{
				centers[j] /= counts[j];
			}
		}

		// print the new centers
		// printf("Iteration: %d\n", iteration);
		// for (int j = 0; j < k; j++)
		//{
		//	printf("Center: %d, Value: %d\n", j, centers[j]);
		//}

		// sleep(1);
	}
	/*
	// iterate through the clusters and print the values
	uint64_t inertia = 0;
	for(int i = 0; i < n; i++){
		inertia += pow(data[i] - centers[clusters[i]], 2);
	}
	printf("Inertia: %ld\n", inertia);
	*/

	return centers;
}

uint64_t *extract_diffBuffer(uint8_t *buffer, uint64_t profile_size, uint64_t *size)
{

#define PASS asm("nop")

	for (int i = 0; i < 1000000; i++)
		PASS;
#define WINDOW 64

	uint64_t *measurementBuffer = (uint64_t *)malloc(PAGE_COUNT * sizeof(uint64_t));
	uint64_t *diffBuffer = (uint64_t *)malloc(PAGE_COUNT * sizeof(uint64_t));

	uint32_t tt = 0;
	uint64_t total = 0;
	int t2_prev = 0;

	if (profile_size > PAGE_COUNT)
	{
		profile_size = PAGE_COUNT;
	}

	for (int p = WINDOW; p < profile_size; p++)
	{
		total = 0;
		int cc = 0;
		for (int r = 0; r < SPOILER_ROUNDS; r++)
		{
			for (int i = WINDOW; i >= 0; i--)
			{
				buffer[(p - i) * PAGE_SIZE] = 0;
			}
			measure(buffer, &tt);

			total += tt;
			cc++;
		}

		if (cc > 0)
		{
			uint64_t result = total / cc;
			measurementBuffer[p] = result;
			if (total / SPOILER_ROUNDS < t2_prev)
			{
				diffBuffer[p] = 0;
			}
			else
			{
				diffBuffer[p] = (total / SPOILER_ROUNDS) - t2_prev;
			}
			(*size)++;
		}
		t2_prev = total / SPOILER_ROUNDS;
	}

	// Cleanup and return
	free(measurementBuffer);
	return diffBuffer;
}

void analyze_and_print_cluster(uint8_t *buffer, int cluster_index)
{
	// Extract the diffBuffer
	// Time how long it takes to extract the diffBuffer
	printf("Extracting diffBuffer\n");
	clock_t start = clock();

	uint64_t size;
	uint64_t profile_size = 10000;
	uint64_t *diffBuffer = extract_diffBuffer(buffer, profile_size, &size);

	// uint64_t diffBuffer[] = { 8, 1, 0, 202, 9, 10, 8, 10, 200, 201, 200, 2};
	// size = 12;
	clock_t end = clock();
	printf("Time to extract diffBuffer: %f\n", (double)(end - start) / CLOCKS_PER_SEC);
	printf("Size: %ld\n", size);

	// Create and array
	// uint64_t data[] = { 8, 1, 0, 202, 9, 10, 8, 10, 200, 201, 200, 2};
	uint64_t *clusters = (uint64_t *)malloc(size * sizeof(uint64_t));
	uint64_t *centers;
	centers = kmeans(diffBuffer, size, 3, 100, clusters);
	// printf("Inertia: %ld\n", calculate_inertia(diffBuffer, size, clusters, 3, centers));
	//  print the centers
	// printf("Centers: %lu, %lu, %lu\n", centers[0], centers[1], centers[2]);

	// Save all the data to a file
	FILE *file = fopen("memory_profiling/logs/cluster.csv", "w+");
	if (file == NULL)
	{
		printf("Error opening file!\n");
		exit(1);
	}
	fprintf(file, "index,diffBuffer,cluster\n");
	for (int i = 0; i < size; i++)
	{
		fprintf(file, "%d,%lu,%lu\n", i, diffBuffer[i], clusters[i]);
	}
	fclose(file);

	// first determine which cluster index has the largest centroid
	int largest_index = 0;
	for (int i = 0; i < 3; i++)
	{
		if (centers[i] > centers[largest_index])
		{
			largest_index = i;
		}
	}

	// Print the virtual, physical, and timing measurements in the largest cluster
	// also calculate the standard deviation (based on the centroid)
	uint64_t prev_addr = 0;
	uint64_t sum = 0;
	for (int i = 0; i < size; i++)
	{
		if (clusters[i] == largest_index)
		{
			sum += pow(sub_abs(diffBuffer[i], centers[largest_index]), 2);
		}
	}

	// Calculate the standard deviation
	uint64_t std_dev = sqrt(sum / size);
	// printf("Standard Deviation: %ld\n", std_dev);
	printf("Minimum threshold: %ld\n", centers[largest_index] - std_dev);
	printf("Maximum threshold: %ld\n", centers[largest_index] + std_dev);
	exit(0);
}

void log_measurements(const char *fname, uint64_t *measurementBuffer, size_t count)
{
	FILE *file = fopen(fname, "w+");
	if (file == NULL)
	{
		printf("Error opening file!\n");
		exit(1);
	}
	for (int i = 0; i < count; i++)
	{
		fprintf(file, "%d,%lu\n", i, measurementBuffer[i]);
	}
	fclose(file);
}

struct measurement
{
	uint64_t *measurementBuffer;
	uint64_t *diffBuffer;
};

struct measurement *spoiler_measure(uint8_t *buffer, size_t buf_size, uint8_t *read)
{
	struct measurement *ret = malloc(sizeof(struct measurement));
	size_t page_count = buf_size / PAGE_SIZE;
	ret->measurementBuffer = malloc(page_count * sizeof(uint64_t));
	ret->diffBuffer = malloc(page_count * sizeof(uint64_t));

	////////////////////////////////SPOILER////////////////////////////////////
	// Warmup loop to avoid initial spike in timings
#define PASS asm("nop")

	for (int i = 0; i < 1000000; i++)
		PASS;
#define WINDOW 64
	// JB: do the actual spoiler measurements
	{
		int t2_prev = 0;
		// for each page in [WINDOW...PAGE_COUNT)
		for (int p = WINDOW; p < page_count; p++)
		{
			uint64_t total = 0;
			int cc = 0;
			for (int r = 0; r < SPOILER_ROUNDS; r++)
			{
				uint32_t tt = 0;
				for (int i = WINDOW; i >= 0; i--)
				{
					buffer[(p - i) * PAGE_SIZE] = 0;
				}
				measure(read, &tt);
				// printf("tt = %lu\n", tt);

				if (tt < THRESH_OUTLIER)
				{
					total = total + tt;
					// printf("total = %lu\n", total);
					cc++;
				}
			}

			if (cc > 0)
			{
				uint64_t result = total / cc;
				ret->measurementBuffer[p] = result;
				if (total / SPOILER_ROUNDS < t2_prev)
				{
					ret->diffBuffer[p] = 0;
				}
				else
				{
					ret->diffBuffer[p] = (total / SPOILER_ROUNDS) - t2_prev;
				}
			}
			t2_prev = total / SPOILER_ROUNDS;
		}
	}
	return ret;
}

void spoiler_free(struct measurement *m)
{
	free(m->measurementBuffer);
	free(m->diffBuffer);
	free(m);
}

struct addr_space *auto_spoiler(uint8_t *buffer, size_t buf_size)
{
	clock_t start = clock();
	size_t page_count = buf_size / PAGE_SIZE;
	struct measurement *m = spoiler_measure(buffer, buf_size, buffer);
	log_measurements("measurements.csv", m->measurementBuffer, page_count);
	log_measurements("diffs.csv", m->diffBuffer, page_count);

	const uint64_t THRESH_LOW = 400;
	const uint64_t THRESH_HI = 800;

	// JB: find clusters in diffBuffer, probably for debugging?
	{
		// Logic to find threshold values
		const uint64_t search_space = page_count; // This can be reduced to speed up the process
		assert(search_space <= page_count);

		// Start clock
		clock_t cl = clock();
		uint64_t *clusters = (uint64_t *)malloc(search_space * sizeof(uint64_t));
		uint64_t *centers = (uint64_t *)malloc(3 * sizeof(uint64_t));

		srand((unsigned int)time(NULL)); // kmeans uses random values for initial centers: seed the RNG
		centers = kmeans(m->diffBuffer, search_space, 3, 100, clusters);

		// dump the time measurements and the cluster assignments to a file
		FILE *file = fopen("log/memory_profiling/logs/spoiler_cluster.csv", "w+");
		if (file == NULL)
		{
			printf("Error opening file!\n");
			exit(1);
		}
		fprintf(file, "index,diffBuffer,cluster\n");
		for (int i = 0; i < search_space; i++)
		{
			fprintf(file, "%d,%lu,%lu\n", i, m->diffBuffer[i], clusters[i]);
		}
		fclose(file);

		// printf("Inertia: %ld\n", calculate_inertia(diffBuffer, size, clusters, 3, centers));
		//  print the centers
		printf("Centers: %ld, %ld, %ld\n", centers[0], centers[1], centers[2]);
		// end clock
		cl = clock() - cl;
		float timer = ((float)cl) / CLOCKS_PER_SEC;

		// first determine which cluster index has the largest centroid
		int largest_index = 0;
		for (int i = 0; i < 3; i++)
		{
			if (centers[i] > centers[largest_index])
			{
				largest_index = i;
			}
		}

		uint64_t sum = 0;
		for (int i = 0; i < search_space; i++)
		{
			if (clusters[i] == largest_index)
			{
				sum += pow(sub_abs(m->diffBuffer[i], centers[largest_index]), 2);
			}
		}

		// Calculate the standard deviation
		uint64_t std_dev = sqrt(sum / search_space);
		printf("Standard Deviation: %ld\n", std_dev);
		printf("Minimum threshold: %ld\n", centers[largest_index] - std_dev);
		printf("Maximum threshold: %ld\n", centers[largest_index] + std_dev);

		printf("Time to run kmeans: %f\n", timer);
	}

	// JB: "peaks" is an array of page offsets where diffBuffer is in (THRESH_LOW, THRESH_HI)
	int peaks[PEAKS] = {0}; // Segmentation fault (core dumped) if less than the number of peaks found
	int peak_index = 0;
	int apart[PEAKS] = {0};
	for (int p = 0; p < page_count; p++)
	{
		if (m->diffBuffer[p] > THRESH_LOW && m->diffBuffer[p] < THRESH_HI)
		{
			peaks[peak_index] = p;
			peak_index++;
		}
	}

	// Finding distances between the peaks in terms of # of pages
	for (int j = 0; j < peak_index - 1; j++)
	{
		apart[j] = peaks[j + 1] - peaks[j];
		// printf("apart[%i] = %i\n", j, apart[j]);
	}

	// JB: Find CONT_WINDOW_SIZE distances of 256 pages (1 MiB) between peaks
	// Here 1 unit means 256 pages = 1MB
	// 5 means we are looking for 6 peaks 256 apart = 5MB
	// if changing here, also update the if(apart[j] == 256.....) statement accordingly
	int cont_window = CONT_WINDOW_SIZE;
	int condition;
	int cont_start = 0; // Starting and ending page # for cont_mem
	int cont_end = 0;
	for (int j = 0; j < peak_index - 1 - cont_window; j++)
	{
		condition = 1;
		for (int q = 0; q < cont_window; q++)
		{
			condition = condition && (apart[j + q] == 256);
		}

		// if (apart[j] == 256 && apart[j+1] == 256 && apart[j+2] == 256 && apart[j+3] == 256 && apart[j+4] == 256 && apart[j+5] == 256 && apart[j+6] == 256 && apart[j+7] == 256 && apart[j+8] == 256 && apart[j+9] == 256)
		if (condition)
		{
			clock_t cl = clock() - start;
			float timer = ((float)cl) / CLOCKS_PER_SEC;
			printf("Found %d MB contiguous memory within %luMB buffer in %f seconds.\n", cont_window, page_count * PAGE_SIZE / 1024 / 1024, timer);

			// printf("Contiguous memory found in %f seconds.\n", timer);
			cont_start = peaks[j];
			cont_end = peaks[j + cont_window];
			break;
		}
	}
	if (cont_start == 0)
	{
		printf("Unable to detect required contiguous memory of %dMB within %luMB buffer\n", cont_window, page_count * PAGE_SIZE / 1024 / 1024);
		return NULL;
	}

	struct addr_space *ret = malloc(sizeof(struct addr_space));
	ret->length = cont_end - cont_start;

	ret->memory_addresses = malloc(ret->length * sizeof(uint64_t));

	// printf("length: %d, start: %d, end: %d\n", ret->length, cont_start, cont_end);
	// printf("length: %d pages\n\n", ret->length/PAGE_SIZE);

	for (int i = 0; i < ret->length; i++)
	{
		ret->memory_addresses[i] = &buffer[((cont_start * PAGE_SIZE) + (i * PAGE_SIZE))];
	}
	process_buff(ret, m->measurementBuffer);
	return ret;
	///////////////////////////////////////////////////////////////////////////
}

/*
struct addr_space * spoiler(uint8_t* buffer){

	//analyze_and_print_cluster(buffer, 1);
	//exit(0);

	//system("echo 123456 | /usr/bin/sudo -S sh -c \"echo 1 >> /proc/sys/vm/compact_memory\"");
	srand((unsigned int) time(NULL));
	////////////////////////////////SPOILER////////////////////////////////////
	// Warmup loop to avoid initial spike in timings
	clock_t cl = clock();

	#define PASS asm("nop")

	for (int i = 0; i < 1000000; i++) PASS;
	#define WINDOW 64

	srand((unsigned int) time(NULL));
	float timer = 0.0;


	int peaks[PEAKS] = {0};			// Segmentation fault (core dumped) if less than the number of peaks found
	int peak_index = 0;
	int apart[PEAKS] = {0};


	uint64_t * measurementBuffer = (uint64_t*) malloc(PAGE_COUNT * sizeof(uint64_t));
	uint64_t *diffBuffer = (uint64_t *)malloc(PAGE_COUNT * sizeof(uint64_t));


	uint32_t tt = 0;
	uint64_t total = 0;
	int t2_prev;

	int cont_start = 0;			// Starting and ending page # for cont_mem
	int cont_end = 0;

	t2_prev = 0;
	for (int p = WINDOW; p < PAGE_COUNT; p++)
	{
		total = 0;
		int cc = 0;
		for (int r = 0; r < SPOILER_ROUNDS; r++)
		{
			for(int i = WINDOW; i >= 0; i--)
			{
				buffer[(p-i)*PAGE_SIZE] = 0;
			}
			measure(buffer, &tt);
			//printf("tt = %lu\n", tt);

			if (tt < THRESH_OUTLIER)
			{
				total = total + tt;
				//printf("total = %lu\n", total);
				cc++;
			}
		}

		if(cc > 0){
			measurementBuffer[p] = total / cc; // TODO FLOATING POINT EXCEPTION HERE - check SPOILER tresholds
			diffBuffer[p] = (total / SPOILER_ROUNDS) - t2_prev;
		}
		// Extracting the peaks
		if (total/SPOILER_ROUNDS-t2_prev > THRESH_LOW && total/SPOILER_ROUNDS-t2_prev < THRESH_HI)
		{
			peaks[peak_index] = p;
			peak_index++;
			//printf("Peak at page # %i\n", p);
		}
		t2_prev = total / SPOILER_ROUNDS;
	}

	log_spoiler(buffer, measurementBuffer, diffBuffer);

	// Finding distances between the peaks in terms of # of pages
	for (int j = 0; j < peak_index - 1; j++)
	{
		apart[j] = peaks[j+1] - peaks[j];
		//printf("apart[%i] = %i\n", j, apart[j]);
	}

	// Here 1 unit means 256 pages = 1MB
	// 5 means we are looking for 6 peaks 256 apart = 5MB
	// if changing here, also update the if(apart[j] == 256.....) statement accordingly
	int cont_window = CONT_WINDOW_SIZE;
	int condition;
	for (int j = 0; j < peak_index - 1 - cont_window; j++)
	{
		condition = 1;
		for (int q = 0; q < cont_window; q++)
		{
			condition = condition && (apart[j+q] == 256);
		}

		//if (apart[j] == 256 && apart[j+1] == 256 && apart[j+2] == 256 && apart[j+3] == 256 && apart[j+4] == 256 && apart[j+5] == 256 && apart[j+6] == 256 && apart[j+7] == 256 && apart[j+8] == 256 && apart[j+9] == 256)
		if (condition)
		{
			cl = clock() - cl;
			timer = ((float) cl)/CLOCKS_PER_SEC;
			printf("Found %d MB contiguous memory within %luMB buffer in %f seconds.\n", cont_window, PAGE_COUNT*PAGE_SIZE/1024/1024,timer);

			//printf("Contiguous memory found in %f seconds.\n", timer);
			cont_start = peaks[j];
			cont_end = peaks[j + cont_window];
			break;
		}
	}
	if (cont_start == 0)
	{
		printf("Unable to detect required contiguous memory of %dMB within %luMB buffer\n", cont_window, PAGE_COUNT*PAGE_SIZE/1024/1024);

		uint8_t * search_buffer = mmap(NULL, PAGE_COUNT * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		munmap(buffer, PAGE_COUNT * PAGE_SIZE);
		return spoiler(search_buffer);
	}

	struct addr_space * ret = malloc(sizeof(struct addr_space));
	ret->length = cont_end - cont_start;

	ret->memory_addresses = malloc(ret->length * sizeof(uint64_t));

	//printf("length: %d, start: %d, end: %d\n", ret->length, cont_start, cont_end);
	//printf("length: %d pages\n\n", ret->length/PAGE_SIZE);

	for(int i = 0; i < ret->length; i++){
		ret->memory_addresses[i] = &buffer[((cont_start*PAGE_SIZE) + (i*PAGE_SIZE))];
	}
	process_buff(ret, measurementBuffer);
	return ret;
	///////////////////////////////////////////////////////////////////////////
}


*/

void process_buff(struct addr_space *buff, uint64_t *measurementBuffer)
{
	// Iterate over the buffer and print the physical addresses
	for (int i = 0; i < buff->length; i += PAGE_SIZE)
	{
		uint64_t phys_addr = get_physical_addr((uint64_t)buff->memory_addresses[i]);
		int bank = phys_2_dram(phys_addr).bank;
		int row = phys_2_dram(phys_addr).row;
		printf("vaddr: %p, paddr: %lx, bank: %d, row: %d, time: %ld\n", buff->memory_addresses[i], phys_addr, bank, row, measurementBuffer[i / PAGE_SIZE]);
	}
}

void log_spoiler(uint8_t *buffer, uint64_t *measurementBuffer, uint64_t *diffBuffer)
{
	const char *directory = "memory_profiling";
	const char *filename = "memory_profiling/logs/spoiler.csv";

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
	FILE *t2_file = fopen(filename, "w+");
	if (!t2_file)
	{
		perror("Error opening Spoiler log");
		return;
	}
	fprintf(t2_file, "vaddr,physaddr,bank,row,abs_store_time,diff_store_time\n");

	// Loop through each page and log the details to the file
	for (int p = 0; p < PAGE_COUNT; p++)
	{
		uint64_t phys_addr = get_physical_addr((uint64_t)&buffer[p * PAGE_SIZE]);
		int bank = phys_2_dram(phys_addr).bank;
		int row = phys_2_dram(phys_addr).row;
		fprintf(t2_file, "0x%lx,0x%lx,%d,%d,%ld,%ld\n", (uint64_t)&buffer[p * PAGE_SIZE], phys_addr, bank, row, measurementBuffer[p], diffBuffer[p]);
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
	fclose(t2_file);
}

inline uint8_t **memory_addresses(const struct addr_space *addr)
{
	return addr->memory_addresses;
}

inline int length(const struct addr_space *addr)
{
	return addr->length;
}

const uint64_t *measurements(const struct measurement *m)
{
	return m->measurementBuffer;
}

const uint64_t *diffs(const struct measurement *m)
{
	return m->diffBuffer;
}
