#include "macho-export.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "loader.h"

static int find_dyld_info(void *file, uint64_t *export_off, size_t *export_sz) {
	struct mach_header_64 *header=file;
	if(header->magic!=MH_MAGIC_64) {
		fprintf(stderr,"Not a valid 64-bit mach-o file.\n");
		return 0;
	}
	for(struct dyld_info_command *cmd=(struct dyld_info_command*)(header+1);cmd!=(void*)(header+1)+header->sizeofcmds;cmd=(void*)cmd+cmd->cmdsize) {
		if(cmd->cmd!=LC_DYLD_INFO&&cmd->cmd!=LC_DYLD_INFO_ONLY)
			continue;
		*export_off=cmd->export_off;
		*export_sz=cmd->export_size;
		return 1;
	}
	fprintf(stderr,"Failed to find dyld info command\n");
	return 0;
}

int main(int argc, char *argv[]) {
	if(argc!=2) {
		fprintf(stderr,"%s <mach-o file>\n",argv[0]);
		return 1;
	}
	int fd=open(argv[1],O_RDONLY);
	if(fd==-1) {
		perror("Failed to open file");
		return 2;
	}
	struct stat fst;
	fstat(fd,&fst);
	void *file=mmap(NULL,fst.st_size,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0);
	if(file==MAP_FAILED) {
		perror("Failed to map file");
		close(fd);
		return 2;
	}
	close(fd);
	uint64_t exp_off;
	size_t exp_sz;
	if(!find_dyld_info(file,&exp_off,&exp_sz)) {
		munmap(file,fst.st_size);
		return 2;
	}
	void *export_blob=file+exp_off;
	printf("exp sz: %u\n",exp_sz);
	struct macho_export_symtab *smt=macho_export_read(export_blob,exp_sz);
	for(struct macho_export_symbol **i=&smt->symbols;*i;) {
		printf("%s: %p",(*i)->symbol_name,(void*)(uint64_t)(*i)->data);
		if(strcmp((*i)->symbol_name,"_main")!=0&&strcmp((*i)->symbol_name,"__mh_execute_header")!=0) {
			puts(" (removing)");
			macho_export_remove(smt,(*i)->symbol_name);
		}else{
			puts("");
			i=&((*i)->next);
		}
	}
	uint32_t size;
	void *data=macho_export_make(smt,&size);
	printf("sz=%u\n",size);
	/*struct macho_export_symtab *newsmt=macho_export_read(data,size);
	for(struct macho_export_symbol **i=&newsmt->symbols;*i;i=&((*i)->next)) {
		printf("%s: %p\n",(*i)->symbol_name,(void*)(uint64_t)(*i)->data);
	}
	macho_export_free(newsmt);*/
	int outdatafd=open("outdata",O_WRONLY|O_CREAT|O_TRUNC,0644);
	write(outdatafd,data,size);
	close(outdatafd);
	if(size<=exp_sz) {
		memcpy(export_blob,data,size);
		int outfd=open("output",O_WRONLY|O_CREAT|O_TRUNC,0755);
		write(outfd,file,fst.st_size);
		close(outfd);
	}else{
		fprintf(stderr, "Data too large, cannot write\n");
	}
	free(data);
	macho_export_free(smt);
	munmap(file,fst.st_size);
	return 0;
}
