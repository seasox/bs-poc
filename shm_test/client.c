#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../victims/lib/memutils/memutils.h"

int main(void) {
	int shm = shm_open("FOO2_SHM", O_RDONLY, S_IRUSR | S_IWUSR);
	if (shm < 0) {
		perror("shm_open");
		return 1;
	}
	int *x = mmap(NULL, 2*sizeof(int), PROT_READ, MAP_SHARED | MAP_POPULATE, shm, 0);
	if (x == MAP_FAILED) {
		perror("mmap");
		shm_unlink("FOO2_SHM");
		return 1;
	}
	while (1) {
		printf("x = [ %d, %d ]\n", x[0], x[1]);
		printf("0x%lx\n", get_physical_address(x));
	}
	shm_unlink("FOO2_SHM");
	return 0;
}
