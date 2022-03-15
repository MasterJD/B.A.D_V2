#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"

void syscall_init (void);

struct child_process {
  int pid;
  int load_status;
  int wait;
  int exit;
  int status;
  struct semaphore load_sema;
  struct semaphore exit_sema;
  struct list_elem elem;
};

struct process_file {
    struct file *file;
    int fd;
    struct list_elem elem;
};

struct lock file_system_lock;

int getpage_ptr (const void *vaddr);
struct child_process* find_child_process (int pid);
void remove_child_process (struct child_process *child);
void remove_all_child_processes (void);
struct file* get_file(int filedes);
void process_close_file (int file_descriptor);
void syscall_exit (int status);


#endif /* userprog/syscall.h */
