#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../victims/lib/memutils/memutils.h"

int main(void) {
	shm_unlink("FOO2_SHM");
	int shm = shm_open("FOO2_SHM", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (shm < 0) {
		perror("shm_open");
		return 1;
	}
	if (ftruncate(shm, 2*sizeof(int)) == -1) {
		shm_unlink("FOO2_SHM");
		perror("ftruncate");
		return 1;
	}
	int *x = mmap(NULL, 2*sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, shm, 0);
	if (x == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	x[0] = 0;
	x[1] = 1;
	printf("0x%lx\n", get_physical_address(x));
	while (1) {
		x[1] = x[0];
		x[0] = !x[0];
	}
	shm_unlink("FOO2_SHM");
	return 0;
}
