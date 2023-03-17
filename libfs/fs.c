#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define FAT_EOC 0xFFFF

int offset_to_block(int, size_t);
int add_data_block(int);
void free_all(void);
int allocate_data_block(void);

/* TODO: Phase 1 */
struct __attribute__((__packed__)) superblock{
	char signature[8];
	uint16_t total_blocks;
	uint16_t root_dir_index;
	uint16_t data_block_start;
	uint16_t data_block_amount;
	uint8_t fat_block_amount;
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

struct superblock* sb = NULL;
struct rootdir_entry* rd = NULL;
fat_entry* fat = NULL;
struct file_descriptor_entry* fd_table = NULL;


int fs_mount(const char *diskname)
{
	fat_entry* fat_buffer;
	char expected_sig[8] = {'E','C','S','1','5','0','F','S'};
	sb = malloc(sizeof(struct superblock));
	rd = calloc(128, sizeof(struct rootdir_entry));
	fd_table = calloc(32, sizeof(struct file_descriptor_entry));

	if(block_disk_open(diskname) == -1){
		free_all();
		return -1;
	}

	//read superblock
	if(block_read(0, sb) == -1){
		perror("bad superbloack read");
		free_all();
		return -1;
	}

	//verify filesystem format
	if (memcmp(sb->signature, expected_sig, 8) != 0){
		perror("invalid signature");
		free_all();
		return -1;	
	}

	if (block_disk_count() != sb->total_blocks){
		perror("invalid block disk count");
		free_all();
		return -1;	
	}

	if (sb->fat_block_amount+1 != sb->root_dir_index){
		perror("invalid root dir index");
		free_all();
		return -1;	
	}

	//allocate and read FAT
	fat = malloc(sizeof(fat_entry) * sb->data_block_amount);
		//this may underallocate space (ie in the case of 2 data blocks)
		//to fix, block read into fat_buffer and then memcpy the buffer into the fat]
	fat_buffer = malloc(sb->fat_block_amount * BLOCK_SIZE);
	for(int i=1; i <= sb->fat_block_amount; i++){
		if(block_read(i,(void*)fat_buffer+(BLOCK_SIZE*(i-1))) == -1){
			perror("bad fat read");
			free_all();
			return -1;
		}
	}
	memcpy(fat, fat_buffer, sizeof(fat_entry) * sb->data_block_amount);
	free(fat_buffer);

	//verify FAT format
	if(fat[0] != FAT_EOC){
		perror("invalid fat format");
		free_all();
		return -1;
	}

	//read root directory
	if(block_read(sb->root_dir_index, rd) == -1){
		perror("bad root dir read");
		free_all();
		return -1;
	}
	return 0;
	/* TODO: Phase 1 */
}

void free_all(void){
	free(sb);
	free(rd);
	free(fat);
	free(fd_table);
}

int fs_umount(void)
{
	fat_entry* fat_buffer;
	fat_buffer = malloc(sb->fat_block_amount * BLOCK_SIZE);

	if(sb == NULL){
		perror("no filesystem mounted");
		return -1;
	}
	for(int i=0; i<FS_OPEN_MAX_COUNT; i++){
		if(fd_table[i].filename[0] != '\0'){
			perror("open file descriptors");
			return -1;
		}
	}

	//persist changes made to the fat
	memcpy(fat_buffer, fat, sizeof(fat_entry) * sb->data_block_amount);
	for(int i=1; i <= sb->fat_block_amount; i++){
		if(block_write(i,(void*)fat_buffer+(BLOCK_SIZE*(i-1))) == -1){
			perror("bad fat write");
			return -1;
		}
	}
	free(fat_buffer);

	//persist changes made to the root dir
	if(block_write(sb->root_dir_index, rd) == -1){
		perror("bad root dir read");
		return -1;
	}

	if(block_disk_close() == -1){
		perror("virtual disk cannot be closed");
		return -1;
	}

	if(sb != NULL){
		free(sb);
		sb = NULL;
	}
	if(rd != NULL){
		free(rd);
		rd = NULL;
	}
	if(fat != NULL){
		free(fat);
		fat = NULL;
	}
	if(fd_table != NULL){
		free(fd_table);
		fd_table = NULL;
	}

	return 0;
	/* TODO: Phase 1 */
}

int fs_info(void)
{
	int free_fat = 0;
	int free_rd = 0;
	if(sb == NULL){
		perror("no virtual disk opened");
		return -1;
	}
	printf("%s \n", "FS Info:");
	printf("%s%d\n", "total_blk_count=", sb->total_blocks);
	printf("%s%d\n", "fat_blk_count=", sb->fat_block_amount);
	printf("%s%d\n", "rdir_blk=", sb->root_dir_index);
	printf("%s%d\n", "data_blk=", sb->data_block_start);
	printf("%s%d\n", "data_blk_count=", sb->data_block_amount);
	
	for(int i=0; i<sb->data_block_amount; i++){
		if(fat[i] == 0){
			free_fat++;
		}
	}
	printf("fat_free_ratio=%d/%d\n", free_fat, sb->data_block_amount);

	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
		if(rd[i].filename[0] == '\0'){
			free_rd++;
		}
	}
	printf("rdir_free_ratio=%d/%d\n", free_rd, FS_FILE_MAX_COUNT);

	return 0;
	/* TODO: Phase 1 */
}

int fs_create(const char *filename)
{
	//check error handling
	if(sb == NULL){
		perror("no filesystem mounted");
		return -1;
	}
	if(memchr(filename, '\0', 16) == NULL || memchr(filename, '\0', 16) == filename){
		perror("invalid filename");
		return -1;
	}
	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
		if(strcmp(rd[i].filename, filename) == 0){
			perror("filename already exists");
			return -1;
		}
	}
	if(strlen(filename) > FS_FILENAME_LEN-1){
		perror("filename is too long");
		return -1;
	}

	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
		if(rd[i].filename[0] == '\0'){
			strncpy(rd[i].filename, filename, FS_FILENAME_LEN);
			rd[i].file_size = 0;
			rd[i].block_index = FAT_EOC;
			return 0;
		}
		else{}
	}
	perror("root directory has max number of files");
	return -1;
	/* TODO: Phase 2 */
}

int fs_delete(const char *filename)
{
	uint16_t fat_index_looper = 0;
	uint16_t next_index = 0;
	int file_found = 0;
	
	if(sb == NULL){
		perror("no filesystem mounted");
		return -1;
	}
	if(memchr(filename, '\0', 16) == NULL || memchr(filename, '\0', 16) == filename){
		perror("invalid filename");
		return -1;
	}
	for(int i=0; i<FS_OPEN_MAX_COUNT; i++){
		if(strcmp(fd_table[i].filename, filename) == 0){
			perror("file is currently open");
			return -1;
		}
	}

	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
		if(strcmp(rd[i].filename, filename) == 0){
			fat_index_looper = rd[i].block_index;
			memset(&rd[i], 0, sizeof(struct rootdir_entry));
			file_found = 1;
			break;
		}
	}

	if(file_found == 0){
		perror("no file of that name found");
		return -1;
	}

	if(fat_index_looper != FAT_EOC){
		while(fat[fat_index_looper] != FAT_EOC){
			next_index = fat[fat_index_looper];
			fat[fat_index_looper] = 0;
			fat_index_looper = next_index;
		}
		fat[fat_index_looper] = 0;
		}
	return 0;
	/* TODO: Phase 2 */
}

int fs_ls(void)
{
	if(sb == NULL){
		perror("no filesystem mounted");
		return -1;
	}
	printf("%s \n","FS Ls:");
	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
		if(rd[i].filename[0] == '\0'){
		}
		else{
			printf("file: %s, size: %d, data_blk: %d\n", rd[i].filename, rd[i].file_size, rd[i].block_index);
		}
	}
	return 0;
	/* TODO: Phase 2 */
}

int fs_open(const char *filename)
{
	int file_desc = -1;
	int file_found = 0;

	if(sb == NULL){
		perror("no filesystem mounted");
		return -1;
	}
	if(memchr(filename, '\0', 16) == NULL || memchr(filename, '\0', 16) == filename){
		perror("invalid filename");
		return -1;
	}
	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
		if(!strcmp(rd[i].filename, filename)){
			file_found = 1;
		}
	}
	if(file_found == 0){
		perror("no file of that name found");
		return -1;
	}

	for(int i=0; i<FS_OPEN_MAX_COUNT; i++){
		if(fd_table[i].filename[0] == '\0'){
			file_desc = i;
			strncpy(fd_table[i].filename, filename, FS_FILENAME_LEN);
			fd_table[i].offset = 0;
			break;
		}
		else{}
	}

	if(file_desc == -1){
		perror("max number of files are open");
		return file_desc;
	}

	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
		if(!strcmp(rd[i].filename, filename)){
			fd_table[file_desc].block_index = rd[i].block_index;
			break;
		}
	}
	return file_desc;
	/* TODO: Phase 3 */
}

int fs_close(int fd)
{
	if(sb == NULL){
		perror("no filesystem mounted");
		return -1;
	}
	if(fd > FS_OPEN_MAX_COUNT-1 || fd_table[fd].filename[0] == '\0'){
		perror("invalid file descriptor");
		return -1;
	}

	memset(&fd_table[fd], 0, sizeof(struct file_descriptor_entry));
	return 0;
	/* TODO: Phase 3 */
}

int fs_stat(int fd)
{
	int file_size = -1;
	
	if(sb == NULL){
		perror("no filesystem mounted");
		return -1;
	}
	if(fd > FS_OPEN_MAX_COUNT-1 || fd_table[fd].filename[0] == '\0'){
		perror("invalid file descriptor");
		return -1;
	}

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
	if(sb == NULL){
		perror("no filesystem is currently mounted");
		return -1;
	}
	if(fd > FS_OPEN_MAX_COUNT-1 || fd_table[fd].filename[0] == '\0'){
		perror("invalid file descriptor");
		return -1;
	}
	if(fs_stat(fd) < (int)offset){
		perror("offset is larger than file size");
		return -1;
	}
	fd_table[fd].offset = offset;
	return 0;
	/* TODO: Phase 3 */
}

int fs_write(int fd, void *buf, size_t count)
{
	int block_offset = 0;
	int amount_to_write = 0;
	int amount_written = 0;
	char dirty_buf[BLOCK_SIZE];
	
	int rootdir_index = 0;
	int new_block = 0;

	if(sb == NULL){
		perror("no filesystem is currently mounted");
		return -1;
	}
	if(fd > FS_OPEN_MAX_COUNT-1 || fd_table[fd].filename[0] == '\0'){
		perror("invalid file descriptor");
		return -1;
	}
	if(buf == NULL){
		perror("invalid buffer");
		return -1;
	}

	for(int i=0; i<FS_FILE_MAX_COUNT; i++){
		if(!strcmp(rd[i].filename, fd_table[fd].filename)){
			rootdir_index = i;
			break;
		}
	}
	//if file is empty (has no allocated blocked)
	//allocate first block, update rd and fd
	if(rd[rootdir_index].block_index == FAT_EOC && count > 0){
		 new_block = allocate_data_block();
		 if(new_block == -1){
			return -1;
		 }
		 else{
			rd[rootdir_index].block_index = new_block;
			fd_table[fd].block_index = new_block;
		 }
	}

	while(count > 0 && offset_to_block(fd, fd_table[fd].offset) != FAT_EOC){
		block_read(offset_to_block(fd, fd_table[fd].offset), dirty_buf);
		
		block_offset = fd_table[fd].offset%BLOCK_SIZE;
		
		if(block_offset+count < BLOCK_SIZE){
			amount_to_write = count;
		}
		else{
			amount_to_write = BLOCK_SIZE-block_offset;
		}
		memcpy(dirty_buf+block_offset, buf, amount_to_write);
		block_write(offset_to_block(fd, fd_table[fd].offset), dirty_buf);
		amount_written += amount_to_write;
		fd_table[fd].offset += amount_to_write;
		count -= amount_to_write;
		buf += amount_to_write;
		//should we modify the rd entry for the file to increase the size ?
		rd[rootdir_index].file_size += amount_to_write;

		if(offset_to_block(fd, fd_table[fd].offset) == FAT_EOC){
			if(add_data_block(fd) == -1){
				break;
				//if disk is full, break
			}
		}
	}
	return amount_written;
	/* TODO: Phase 4 */
}

int fs_read(int fd, void *buf, size_t count)
{
	int block_offset = 0;
	int amount_to_read = 0;
	int amount_read = 0;

	char bounce_buf[BLOCK_SIZE];

	if(sb == NULL){
		perror("no filesystem is currently mounted");
		return -1;
	}
	if(fd > FS_OPEN_MAX_COUNT-1 || fd_table[fd].filename[0] == '\0'){
		perror("invalid file descriptor");
		return -1;
	}
	if(buf == NULL){
		perror("invalid buffer");
		return -1;
	}
	
	if((int)(fd_table[fd].offset+count) > fs_stat(fd)){
		//set count to number of bytes until the end of file
		count = fs_stat(fd) - fd_table[fd].offset;
	}

	while(count > 0){
		//read entire block
		block_read(offset_to_block(fd, fd_table[fd].offset), bounce_buf);
		
		//where in the block do we want to start
		block_offset = fd_table[fd].offset%BLOCK_SIZE;
		
		//if all we want to read is within the same block,
		// set amount_to_read to count
		if(block_offset+count < BLOCK_SIZE){
			amount_to_read = count;
		}
		//if we need to read from multiple blocks
		// set amount to read to be rest of the initial block
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
	int actual_block;
	//set fat looper to first data block for the file
	uint16_t fat_looper = fd_table[fd].block_index;
	//how many "blocks" in we are into the file
	block_number = offset/BLOCK_SIZE;
	//loop fat table to find the index of the data block we want (ie the info inside the FAT entry)
	for(int i=0; i<block_number; i++){
		fat_looper = fat[fat_looper];
		if(fat_looper == FAT_EOC){
			return fat_looper;
		}
	}
	//return actual index of the data block (including offset from superblock, block for root dir, and fat blocks)
	actual_block = fat_looper + 1 + 1 + sb->fat_block_amount;
	return actual_block;
}

int add_data_block(int fd){
	int new_block_index = -1;
	uint16_t fat_looper = fd_table[fd].block_index;

	for(int i=0; i < sb->data_block_amount; i++){
		if(fat[i] == 0){
			new_block_index = i;
			break;
		}
	}
	if(new_block_index == -1){
		return -1;
	}

	while(fat[fat_looper] != FAT_EOC){
		fat_looper = fat[fat_looper];
	}

	fat[fat_looper] = new_block_index;
	fat[new_block_index] = FAT_EOC;
	return new_block_index;
}

int allocate_data_block(void){
	int new_block_index = -1;
	
	for(int i=0; i < sb->data_block_amount; i++){
		if(fat[i] == 0){
			new_block_index = i;
			break;
		}
	}
	
	if(new_block_index != -1){
		fat[new_block_index] = FAT_EOC;
	}

	return new_block_index;
}
