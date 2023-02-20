/*
 * Title:  userland exec header (Linux)
 * Author: Shuichiro Endo
 */

unsigned long load_elf(pid_t pid, struct user_regs_struct regs, unsigned long tmp_address, unsigned char *elf_file, unsigned long base_address);

typedef struct {
	unsigned long type;
	unsigned long data;
} AUX_VECTOR, *pAUX_VECTOR;


