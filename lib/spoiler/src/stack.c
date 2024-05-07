#include "../include/stack.h"


uint64_t find_integer_in_stack(StackEntry *stack_entries, int num_entries, uint64_t target_value)
{
	for (int i = 0; i < num_entries; ++i)
	{
		if (stack_entries[i].value == target_value)
		{
			return stack_entries[i].address;
		}
	}
	return 0; // Return 0 if the integer is not found
}

int read_stack(pid_t pid, StackEntry **stack_entries)
{
	char maps_path[50];
	sprintf(maps_path, "/proc/%d/maps", pid);

	FILE *maps_file = fopen(maps_path, "r");
	if (maps_file == NULL)
	{
		perror("Could not open maps file");
		return -1;
	}

	char line[256];
	regex_t regex;
	regmatch_t matches[3]; // We expect 2 groups + entire match

	if (regcomp(&regex, "([0-9a-f]+)-([0-9a-f]+) .* \\[stack\\]", REG_EXTENDED) != 0)
	{
		perror("Could not compile regular expression");
		return -1;
	}

	uint64_t start = 0, end = 0;
	while (fgets(line, sizeof(line), maps_file))
	{
		if (regexec(&regex, line, 3, matches, 0) == 0)
		{
			line[matches[1].rm_eo] = 0;
			line[matches[2].rm_eo] = 0;
			start = strtoull(&line[matches[1].rm_so], NULL, 16);
			end = strtoull(&line[matches[2].rm_so], NULL, 16);
			break;
		}
	}

	fclose(maps_file);
	regfree(&regex);

	if (start == 0 || end == 0)
	{
		printf("Could not find stack information.\n");
		return -1;
	}

	char mem_path[50];
	sprintf(mem_path, "/proc/%d/mem", pid);

	int mem_file = open(mem_path, O_RDONLY);
	if (mem_file < 0)
	{
		perror("Could not open mem file");
		return -1;
	}

	lseek(mem_file, start, SEEK_SET);
	size_t length = end - start;
	uint8_t *stack_content = malloc(length);
	if (read(mem_file, stack_content, length) != length)
	{
		perror("Could not read stack content");
		return -1;
	}
	close(mem_file);

	FILE *csv_file = fopen("stack_content.csv", "w");
	if (csv_file == NULL)
	{
		perror("Could not open stack_content.csv for writing");
		return -1;
	}

	int num_entries = length / 8;
	*stack_entries = malloc(num_entries * sizeof(StackEntry));
	for (int i = 0; i < num_entries; ++i)
	{
		uint64_t value;
		memcpy(&value, &stack_content[i * 8], 8);
		fprintf(csv_file, "%lx,%lx\n", start + i * 8, value);
		(*stack_entries)[i].address = start + i * 8;
		(*stack_entries)[i].value = value;
	}

	fclose(csv_file);
	free(stack_content);

	return num_entries;
}