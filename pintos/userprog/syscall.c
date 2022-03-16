#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define MAX_ARGS 3

static void syscall_handler(struct intr_frame *);
int add_file(struct file *file_name);
void get_args(struct intr_frame *f, int *arg, int num_of_args);

void syscall_halt(void);
pid_t syscall_exec(const char* cmdline);
int syscall_wait(pid_t pid);
bool syscall_create(const char* file_name, unsigned starting_size);
bool syscall_remove(const char* file_name);
int syscall_open(const char * file_name);
int syscall_filesize(int filedes);
int syscall_read(int filedes, void *buffer, unsigned length);
int syscall_write (int filedes, const void * buffer, unsigned byte_size);
void syscall_seek (int filedes, unsigned new_position);
unsigned syscall_tell(int fildes);
void syscall_close(int filedes);

void validate_ptr (const void* vaddr);
void validate_str (const void* str);
void validate_buffer (const void* buf, unsigned byte_size);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}


  int arg[MAX_ARGS];
  int esp = getpage_ptr((const void *) f->esp);
  
  switch (* (int *) esp){
    case SYS_HALT:
      syscall_halt();
      break;

    case SYS_EXIT:
      get_args(f, &arg[0], 1);
      syscall_exit(arg[0]);
      break;

    case SYS_EXEC:
      get_args(f, &arg[0], 1);
      validate_str((const void*)arg[0]);
      arg[0] = getpage_ptr((const void *)arg[0]);
      f->eax = syscall_exec((const char*)arg[0]);
      break;

    case SYS_CREATE
      get_args(f, &arg[0], 1);
      validate_str((const void*)arg[0]);
      arg[0] = getpage_ptr((const void*));
      f->eax = syscall_create((const char*)arg[0], (unsigned)arg[1]);
      break;





void get_args(struct intr_frame *f, int *args, int numero_args){
  int i, *ptr;
  for (i = 0; i < numero_args; i++){
    ptr = (int *) f->esp + i + 1;
    validate_ptr((const void *) ptr);
    args[i] = *ptr;
  }
}

int getpage_ptr(const void *vaddr){
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr){
    syscall_exit(ERROR);
  }

  return (int)ptr;
}

void validate_ptr (const void *vaddr)}{
    if (vaddr < USER_VADDR_BOTTOM || !is_user_vaddr(vaddr)){
      syscall_exit(ERROR);
    }
}


void validate_str (const void* str){
    for (; * (char *) getpage_ptr(str) != 0; str = (char *) str + 1);
}

void validate_buffer(const void* bufffer, unsigned byte_size){
  unsigned i = 0;
  char* local_buffer = (char *)bufffer;
  for (; i < byte_size; i++){
    validate_ptr((const void*)local_buffer);
    local_buffer++;
  }
}

/*SYSCALLS*/

void syscall_halt (void){
  shutdown_power_off(); /
}

void syscall_exit (int status){
  struct thread *cur = thread_current();
  if (is_thread_alive(cur->parent) && cur->cp){
    if (status < 0){
      status = -1;
    }
    cur->cp->status = status;
  }
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}



