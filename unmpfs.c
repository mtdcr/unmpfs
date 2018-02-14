/*
 * unwmpfs - Extracts files from ATEN PDU firmware archives.
 *
 * Copyright 2018 Andreas Oberritter
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _DEFAULT_SOURCE
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#define ARRAY_SIZE(x)	(sizeof((x))/sizeof(*(x)))

static void _chdir(const char *path)
{
	int ret;

	ret = chdir(path);
	assert(ret == 0);
}

static void _mkdir(const char *path, mode_t mode)
{
	struct stat st;
	int ret;

	if (!strcmp(path, "."))
		return;

	assert(path[0] != '\0');
	assert(path[0] != '/');
	assert(strcmp(path, ".."));

	if (stat(path, &st) != 0 && errno == ENOENT) {
		ret = mkdir(path, mode);
		assert(ret == 0);
	} else {
		assert(S_ISDIR(st.st_mode));
	}
}

static void _mkdir_p(char *path, mode_t mode)
{
	char *s;

	s = strchr(path, '/');
	while (s && *s == '/')
		*s++ = 0;

	_mkdir(path, mode);

	if (s != 0) {
		int fd = open(".", O_RDONLY);
		assert(fd >= 0);
		_chdir(path);
		_mkdir_p(s, mode);
		fchdir(fd);
		close(fd);
	}
}

static void mkdir_p_fn(const char *path, mode_t mode)
{
	char *s;
	size_t n;

	n = strlen(path) + 1;

	s = malloc(n);
	assert(s != NULL);
	memcpy(s, path, n);

	_mkdir_p(dirname(s), mode);

	free(s);
}

static void save_buf(const char *path, const unsigned char *buf, size_t size, mode_t mode, time_t time)
{
	FILE *f;

	while (*path == '/')
		path++;

	mkdir_p_fn(path, 0777);

	f = fopen(path, "w");
	assert(f != NULL);
	fwrite(buf, size, 1, f);
	fclose(f);

	chmod(path, mode);

	struct utimbuf times = {
		.actime = time,
		.modtime = time,
	};
	utime(path, &times);
}

static void hexdump(const char *str, const unsigned char *buf, size_t n)
{
	size_t i;

	printf("%s:", str);

	for (i = 0; i < n; i++)
		printf(" %02x", buf[i]);

	printf("\n");
}

static unsigned short le16tohp(const void *ptr)
{
	return le16toh(*(const unsigned short *)ptr);
}

static unsigned int le32tohp(const void *ptr)
{
	return le32toh(*(const unsigned int *)ptr);
}

static void process_mpfs(const unsigned char *mem, size_t size)
{
	uint16_t nr_entries = le16tohp(&mem[6]);
	uint16_t checksum;
	uint32_t name_offset;
	const char *name;
	uint32_t data_offset;
	uint32_t data_size;
	time_t mtime;
	uint16_t flags;
	unsigned int i;
	size_t total_size = nr_entries * 24 + 8;
	size_t largest_offset = total_size;
	uint32_t next_offset = 0;

	printf("MPFS version %u.%u (%u entries)\n", mem[4], mem[5], nr_entries);

	assert(size >= total_size);

	for (i = 0; i < nr_entries; i++) {
		checksum = le16tohp(&mem[8 + i * 2]);
		name_offset = le32tohp(&mem[8 + (nr_entries * 2) + (i * 22)]);
		data_offset = le32tohp(&mem[8 + (nr_entries * 2) + (i * 22) + 4]);
		data_size = le32tohp(&mem[8 + (nr_entries * 2) + (i * 22) + 8]);
		mtime = le32tohp(&mem[8 + (nr_entries * 2) + (i * 22) + 12]);
		flags = le16tohp(&mem[8 + (nr_entries * 2) + (i * 22) + 20]);
		name = (const char *)&mem[name_offset];

		printf("checksum: %#x\n", checksum);
		printf("name_offset: %#x\n", name_offset);
		printf("name: %s\n", name);
		printf("data_offset: %#x\n", data_offset);
		printf("data_size: %#x\n", data_size);
		printf("mtime: %s", ctime(&mtime));
		printf("flags: %#x\n", flags);

		assert(next_offset == 0 || next_offset == data_offset);
		assert(le32tohp(&mem[8 + (nr_entries * 2) + (i * 22) + 16]) == 0);
		assert(size >= data_offset + data_size);

		total_size += strlen(name) + 1;
		total_size += data_size;
		next_offset = data_offset + data_size;
		largest_offset = MAX(largest_offset, next_offset);

		if (name[0] != '\0') {
			char filename[FILENAME_MAX];
			strcpy(filename, name);
			if (flags & 1) {
				assert(!memcmp(&mem[data_offset], "\x1f\x8b\x08", 3));
				strcat(filename, ".gz");
			}
			assert(filename[0] != '.');
			save_buf(filename, &mem[data_offset], data_size, 0644, mtime);
		} else {
			assert(checksum == 0xffff);
			hexdump("data", &mem[data_offset], data_size);
		}

		printf("\n");
	}

	printf("Processed %zu of %zu bytes. Largest offset: %zu\n", total_size, size, largest_offset);
	assert(total_size == largest_offset);
}

static void process_mem(unsigned char *mem, size_t size)
{
	unsigned int offsets[] = { 0, 64 };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(offsets); i++) {
		if (offsets[i] + 8 >= size) {
			fprintf(stderr, "Cannot read MPFS header!\n");
			return;
		}

		if (!memcmp(&mem[offsets[i]], "MPFS", 4)) {
			process_mpfs(&mem[offsets[i]], size - offsets[i]);
			return;
		}
	}

	fprintf(stderr, "Invalid MPFS header\n");
	return;
}

static bool process_file(int fd)
{
	struct stat st;
	void *mem;

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		return false;
	}

	mem = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return false;
	}

	process_mem(mem, st.st_size);
	munmap(mem, st.st_size);
	return true;
}

int main(int argc, char *argv[])
{
	bool ok;
	int i;

	for (i = 1; i < argc; i++) {
		int fd = open(argv[i], O_RDONLY);
		if (fd < 0) {
			perror(argv[i]);
			return 1;
		}

		ok = process_file(fd);
		close(fd);
		if (!ok)
			return 1;
	}

	return 0;
}
