#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define FAT_EOC 0xFFFF

/* TODO: Phase 1 */
struct __attribute__((__packed__)) superblock{
	char signature[8];
	uint16_t virtual_disk;
	uint16_t root_directory;
	uint16_t data_block_start;
	uint16_t data_block_amount;
	uint8_t fat_blocks;
	char unused[4079];
};

typedef uint16_t fat_entry;

struct __attribute__((__packed__)) rootdir_entry{
	char filename[16];
	uint32_t file_size;
	uint16_t block_index;
	char unused[10];
};

struct superblock* sb = NULL;
struct rootdir_entry* rd = NULL;
fat_entry* fat = NULL;

int fs_mount(const char *diskname)
{
	char expected_sig[8] = {'E','C','S','1','5','0','F','S'};
	sb = malloc(sizeof(struct superblock));
	
	rd = calloc(sizeof(struct rootdir_entry),128);

	if(block_disk_open(diskname) == -1){
		free(rd);
		free(sb);
		return -1;
	}

	if(block_read(0, sb) == -1){
		free(rd);
		free(sb);
		block_disk_close();
		return -1;
	}

	if (memcmp(sb->signature, expected_sig, 8) != 0){
		free(rd);
		free(sb);
		block_disk_close();
		return -1;	
	}

	if (block_disk_count() != sb->virtual_disk){
		free(rd);
		free(sb);
		block_disk_close();
		return -1;	
	}

	if (sb->fat_blocks+1 != sb->root_directory){
		free(rd);
		free(sb);
		block_disk_close();
		return -1;	
	}

	fat = malloc(sb->fat_blocks * BLOCK_SIZE);
	for(int i=1; i <= sb->fat_blocks; i++){
		if(block_read(i,fat+(BLOCK_SIZE*(i-1))) == -1){
			free(rd);
			free(sb);
			free(fat);
			block_disk_close();
			return -1;
		}	
	}

	if(fat[0] != FAT_EOC){
		free(rd);
		free(sb);
		free(fat);
		block_disk_close();
		return -1;
	}

	if(block_read(sb->root_directory, rd) == -1){
		free(rd);
		free(sb);
		free(fat);
		block_disk_close();
		return -1;
	}
	

	/* TODO: Phase 1 */
}

int fs_umount(void)
{
	if(sb != NULL){
		free(sb);
	}
	if(rd != NULL){
		free(rd);
	}
	if(fat != NULL){
		free(fat);
	}
	if(block_disk_close() == -1){
		return -1;
	}
	return 0;
	/* TODO: Phase 1 */
}

int fs_info(void)
{
	/* TODO: Phase 1 */
}

int fs_create(const char *filename)
{
	strcpy(rd[0].filename, filename);
	rd[0].file_size = 0;
	rd[0].block_index = FAT_EOC;

	/* TODO: Phase 2 */
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_ls(void)
{
	for(int i=0; i<128; i++){
		if(rd[i].filename[0] == '\0'){
		}
		else{
			printf("%s\n",rd[i].filename);
		}
	}
	/* TODO: Phase 2 */
}

int fs_open(const char *filename)
{
	/* TODO: Phase 3 */
}

int fs_close(int fd)
{
	/* TODO: Phase 3 */
}

int fs_stat(int fd)
{
	/* TODO: Phase 3 */
}

int fs_lseek(int fd, size_t offset)
{
	/* TODO: Phase 3 */
}

int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}

int fs_read(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}

