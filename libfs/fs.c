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

struct file_descriptor_entry{
	char filename[16];
	size_t offset;
	uint16_t block_index;
};

struct file_descriptor_entry* fd_table = NULL;

struct superblock* sb = NULL;
struct rootdir_entry* rd = NULL;
fat_entry* fat = NULL;

int fs_mount(const char *diskname)
{
	char expected_sig[8] = {'E','C','S','1','5','0','F','S'};
	sb = malloc(sizeof(struct superblock));
	rd = calloc(sizeof(struct rootdir_entry),128);
	fd_table = calloc(sizeof(struct file_descriptor_entry),32);

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
		sb = NULL;
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
	if(strlen(filename) > FS_FILENAME_LEN-1){
		return -1;
	}
	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
		if(rd[i].filename[0] == '\0'){
			strncpy(rd[i].filename, filename, FS_FILENAME_LEN);
			rd[i].file_size = 0;
			rd[i].block_index = FAT_EOC;
			break;
		}
		else{}
	}

	/* TODO: Phase 2 */
}

int fs_delete(const char *filename)
{
	uint16_t fat_index_looper = 0;
	uint16_t next_index = 0; 
	
	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
		if(!strcmp(rd[i].filename, filename)){
			fat_index_looper = rd[i].block_index;
			memset(&rd[i], 0, sizeof(struct rootdir_entry));
			break;
		}
	} 
	while(fat[fat_index_looper] != FAT_EOC){
		next_index = fat[fat_index_looper];
		fat[fat_index_looper] = 0;
		fat_index_looper = next_index;
	}
	fat[fat_index_looper] = 0;
	/* TODO: Phase 2 */
}

int fs_ls(void)
{
	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
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
	int file_desc = -1;
	for(int i=0; i<FS_OPEN_MAX_COUNT; i++){
		if(fd_table[i].filename[0] == '\0'){
			file_desc = i;
			strncpy(fd_table[i].filename, filename, FS_FILENAME_LEN);
			fd_table[i].offset = 0;
			break;
		}
		else{}
	}
	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
		if(!strcmp(rd[i].filename, filename)){
			fd_table[file_desc].block_index = rd[i].block_index;
		}
	}
	return file_desc;
	/* TODO: Phase 3 */
}

int fs_close(int fd)
{
	memset(&fd_table[fd], 0, sizeof(struct file_descriptor_entry));
	/* TODO: Phase 3 */
}

int fs_stat(int fd)
{
	int file_size = -1;
	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
		if(!strcmp(rd[i].filename, fd_table[fd].filename)){
			file_size = rd[i].file_size;
			break;
		}
	}
	return file_size;

	/* TODO: Phase 3 */
}

int fs_lseek(int fd, size_t offset)
{
	if(fd_table[fd].filename[0] == '\0' || fs_stat(fd) < offset){
		return -1;
	}
	fd_table[fd].offset = offset;
	return 0;
	/* TODO: Phase 3 */
}

int fs_write(int fd, void *buf, size_t count)
{
	int block_offset = 0;
	int amount_to_read = 0;
	int amount_read = 0;

	char bounce_buf[BLOCK_SIZE];

	while(count > 0 && offset_to_block(fd, fd_table[fd].offset) != FAT_EOC){
		block_read(offset_to_block(fd, fd_table[fd].offset), bounce_buf);
		
		block_offset = fd_table[fd].offset%BLOCK_SIZE;
		
		if(block_offset+count < BLOCK_SIZE){
			amount_to_read = count;
		}
		else{
			amount_to_read = BLOCK_SIZE-block_offset;
		}
		memcpy(buf, bounce_buf+block_offset, amount_to_read);
		amount_read += amount_to_read;
		fd_table[fd].offset += amount_to_read;
		count -= amount_to_read;
		buf += amount_to_read;
	}
	/* TODO: Phase 4 */
}

int fs_read(int fd, void *buf, size_t count)
{
	int block_offset = 0;
	int amount_to_read = 0;
	int amount_read = 0;

	char bounce_buf[BLOCK_SIZE];

	//do we have to check is the amount we wanna read is greater than file size
	if(fd_table[fd].offset+count > fs_stat){
		return -1;
	}

	while(count > 0){
		block_read(offset_to_block(fd, fd_table[fd].offset), bounce_buf);
		
		block_offset = fd_table[fd].offset%BLOCK_SIZE;
		
		if(block_offset+count < BLOCK_SIZE){
			amount_to_read = count;
		}
		else{
			amount_to_read = BLOCK_SIZE-block_offset;
		}
		memcpy(buf, bounce_buf+block_offset, amount_to_read);
		amount_read += amount_to_read;
		fd_table[fd].offset += amount_to_read;
		count -= amount_to_read;
		buf += amount_to_read;
	}
	return amount_read;
	/* TODO: Phase 4 */
}

int offset_to_block(int fd, size_t offset){
	int block_number;
	uint16_t fat_looper = fd_table[fd].block_index;
	block_number = offset/BLOCK_SIZE;
	for(int i=0; i<block_number; i++){
		fat_looper = fat[fat_looper];
		if(fat_looper == FAT_EOC){
			break;
		}
	}
	return fat_looper;
}