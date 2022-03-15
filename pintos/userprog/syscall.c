#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#define MAX_ARGS 3

static void syscall_handler (struct intr_frame *);
void syscall_halt (void);

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