#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
typedef int pid_t;

void syscall_init (void);
struct descriptor_archivo * abrir_archivo(int fd);
//void halt(void);
void exit(int status);
pid_t exec(const char* cmd_line);
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, char* buffer, unsigned size);
int write (int fd, void* buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell (int fd);
void close(int fd);
int wait (pid_t pid);

#endif /* userprog/syscall.h */
