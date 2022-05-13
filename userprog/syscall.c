#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

#include "lib/kernel/stdio.h"
#include "lib/string.h"
#include <stdio.h>
#include <syscall-nr.h>

#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#include "filesys/filesys.h"
#include "filesys/file.h"

#include "devices/timer.h"

#define STDIN_FILENO 0
#define STDOUT_FILENO 1

static void syscall_handler (struct intr_frame *);
static bool verify_pointer(void *pointer); 
void delete_children(struct hash_elem *elem, void *aux);

void delete_parent_from_child(struct hash_elem *elem, void *aux);
void print_children(struct hash_elem *elem, void *aux);
static struct lock file_system_lock;


void 
print_children(struct hash_elem *elem, void *aux UNUSED)
{
  struct children_process *child = hash_entry(elem, struct children_process, elem);
  if (!child) printf("NULL");
  else {struct thread *child_thread = get_thread(child->pid);
  printf("%s -> ", child_thread->name);}
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_system_lock);
  
}


/*
  Handles the syscalls, the input is an interrupt frame that contains the stack. 
  The intr_frame contains the SYS_CODE and up to three SYSCALL arguments.  

  f->esp = SYS_CODE;
  f->esp + 1 = arg1;
  f->esp + 2 = arg2; 
  f->esp + 3 = arg3; 

  Each argument is a pointer, so before  using its value the fuctions has to dereference the pointer. 
  
  ** SEE SYS_EXIT for an example.** 

*/
  void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int status;
  char* cmd_name;
  int tid;
  char* file_name;
  
  int fd;
  unsigned position;
  unsigned size;
  void* buffer;

  if (!verify_pointer(f->esp))
  {
    exit(-1);
  }

  switch (*(int*)f->esp){
    case SYS_HALT:
      halt();
      break;

    // *************************************************************************************************************************************************
    case SYS_EXIT:
      if (!verify_pointer((int*)f->esp + 1))
        exit(-1);
      status = *((int*)f->esp + 1);
      
      exit(status);
      break;

    // *************************************************************************************************************************************************
    case SYS_EXEC:
      cmd_name = (char*)(*((int*)f->esp + 1)); 
      if (!verify_pointer(cmd_name))
        exit(-1);

      f->eax = exec(cmd_name);
      break;

    // *************************************************************************************************************************************************
    case SYS_WAIT:
      if (!verify_pointer((int*)f->esp + 1))
        exit(-1);
      
      tid = *((int*)f->esp + 1); 
      f->eax = wait(tid);
      break;

    // *************************************************************************************************************************************************
    case SYS_READ:
      if (!verify_pointer((int*)f->esp + 1))
        exit(-1);

      if (!verify_pointer((int*)f->esp + 3))
        exit(-1);

      fd = (*((int*)f->esp + 1)); 
      buffer = (char*)(*((int*)f->esp + 2));
      size = (*((int*)f->esp + 3));

      if (!verify_pointer(buffer))
        exit(-1);
      
      f->eax = read(fd, buffer, size);
      break;

    // *************************************************************************************************************************************************
    case SYS_REMOVE:
      file_name = (char*)(*((int*)f->esp + 1)); 
      if (!verify_pointer(file_name))
        exit(-1);
      
      f->eax = remove(file_name);
      break;

    // *************************************************************************************************************************************************
    case SYS_OPEN:
      file_name = (void*)(*((int*)f->esp + 1)); 
      if (!verify_pointer(file_name))
        exit(-1);
      
      f->eax = open(file_name);
      break;

    // *************************************************************************************************************************************************
    case SYS_FILESIZE:
      if (!verify_pointer((int*)f->esp + 1))
        exit(-1);
      
      fd = (*((int*)f->esp + 1)); 
      f->eax = filesize(fd);
      break;

    // *************************************************************************************************************************************************
    case SYS_CREATE: 
      if (!verify_pointer((int*)f->esp + 1))
        exit(-1);
      
      if (!verify_pointer((int*)f->esp + 2))
        exit(-1);
      
      file_name = (char*)(*((int*)f->esp + 1)); 
      if (!verify_pointer(file_name))
        exit(-1);

      size = (*((int*)f->esp + 2));
      f->eax = create(file_name, size);
      break;

    // *************************************************************************************************************************************************
    case SYS_WRITE:
      if (!verify_pointer((int*)f->esp + 1))
        exit(-1);

      if (!verify_pointer((int*)f->esp + 3))
        exit(-1);

      fd = *((int*)f->esp + 1);
      buffer = (void*)(*((int*)f->esp + 2));
      size = *((int*)f->esp + 3);

      if (!verify_pointer(buffer))
        exit(-1);
      f->eax = write(fd, buffer, size);
      break;

    // *************************************************************************************************************************************************
    case SYS_SEEK:
      if (!verify_pointer((int*)f->esp + 1))
        exit(-1);
      
      if (!verify_pointer((int*)f->esp + 2))
        exit(-1);
          
      fd = *((int*)f->esp + 1);
      position = *((int*)f->esp + 2);

      seek(fd, position);
      break;

    // *************************************************************************************************************************************************
    case SYS_TELL:
      if (!verify_pointer((int*)f->esp + 1))
        exit(-1);

      fd = *((int*)f->esp + 1);

      f->eax = tell(fd);
      break;

    // *************************************************************************************************************************************************
    case SYS_CLOSE:
      if (!verify_pointer((int*)f->esp + 1))
        exit(-1);
      
      fd = *((int*)f->esp + 1); 
      close(fd);
      break;
  }
}


/*
  Checks if pointer meets this two conditions: 
    1. Pointer is between PHYS_BASE and 0x08048000
    2. The pointer is allocated in thread page.

*/
bool 
verify_pointer(void *pointer)
{
  struct thread *cur = thread_current(); 
  bool valid = true;

  if (!is_user_vaddr(pointer) || pointer == NULL)
      return false;
  
  if (pagedir_get_page(cur->pagedir, pointer) == NULL)
      return false;
  
  return valid; 
}

//Función que dado como parametro un descriptor de archivo, obtiene el archivo basado en esa información
struct descriptor_archivo *abrir_archivo(int fd){
    struct list *opfiles = &thread_current()->files;
    struct list_elem *files = list_begin(opfiles);    
    for (files = list_begin(opfiles); files != list_end(opfiles); files = list_next(files)){   
      struct descriptor_archivo *opfile  = list_entry(files, struct descriptor_archivo, at);
      if (opfile->fd == fd){
        return opfile;
      }
    }
    return NULL;
}









void 
delete_parent_from_child(struct hash_elem *elem, void *aux UNUSED)
{
  struct children_process *child = hash_entry(elem, struct children_process, elem);
  struct thread *child_thread = get_thread(child->pid);

  if (child_thread)
  {
    child_thread->padre = 0;
  }

}

void 
delete_children(struct hash_elem *elem, void *aux UNUSED)
{
  struct children_process *child = hash_entry(elem, struct children_process, elem);
  free(child);
}

//--------------AQUI EMPIEZAN LAS FUNCIONES PARA LLAMADAS A LOS SYS CALLS--------------

//--------------SYS CALL HALT()--------------
void halt (void) {
  shutdown_power_off();
}

//--------------SYS CALL EXIT()--------------
void exit(int status) {

  printf ("%s: exit(%d)\n", thread_current()->name, status);

  struct thread *cur = thread_current();
  struct thread *par = thread_current()->parent_thread;

  if (thread_alive(cur->tid)) {
    if (par != NULL) {

      for (struct list_elem *e = list_begin (&par->child_obituaries); e != list_end (&par->child_obituaries); e = list_next (e)) {
        struct child_obituary *co = list_entry (e, struct child_obituary, dead_child_elem);
        if (co->pid == cur->tid) {
          co->exit_status = status;
          co->exited = true;
          sema_up(&co->process_wait_sema);
        }
      }

    } 
  }


  thread_exit();
}

//--------------SYS CALL EXECUTE()--------------
pid_t exec(const char* cmd_line){
  return 0;
}
//--------------SYS CALL WAIT()--------------
int wait (pid_t pid) {
  int status = process_wait(pid);
  return status;
}
//--------------SYS CALL CREATE(file, size)--------------
bool create(const char* file, unsigned initial_size){
  lock_acquire(&file_system_lock);
  bool status = filesys_create(file, initial_size);
  lock_release(&file_system_lock);
  return status;
}
//--------------SYS CALL REMOVE(file)--------------
bool remove(const char* file){  
  lock_acquire(&file_system_lock);
  bool status = filesys_remove(file);
  lock_release(&file_system_lock);
  return status;
}
//--------------SYS CALL OPEN(file)--------------
int open(const char* file){
  return -1;
}
//--------------SYS CALL FILESIZE(filedescriptor)--------------
int filesize(int fd){
  struct descriptor_archivo *archivo_abierto = abrir_archivo(fd);
  struct file *archivo = archivo_abierto->tfiles;
  lock_acquire(&file_system_lock);
  int status = file_length(archivo);
  lock_release(&file_system_lock);
  return status;
  }
//--------------SYS CALL READ(filedescriptor, buffer, size)--------------
int read(int fd, char* buffer, unsigned size){
  return 0;
}
//--------------SYS CALL WRITE(filedescriptor, buffer, size)--------------
int write (int fd, void* buffer, unsigned size){
  
  if (fd == STDIN_FILENO){
    return 0;
  }
  else if(fd == STDOUT_FILENO){
    putbuf(buffer, size);
    return size;
  }
  else{
    struct descriptor_archivo *archivo_abierto = abrir_archivo(fd);
    int bytes_escritos = -1;

    if (archivo_abierto == NULL){
      return 0;
    }
    lock_acquire(&file_system_lock);
    bytes_escritos = file_write(archivo_abierto->tfiles, buffer, size);
    lock_release(&file_system_lock);
    return bytes_escritos;
  }
}
//--------------SYS CALL SEEK(filedescriptor, position)--------------
void seek(int fd, unsigned position){
  int size = filesize(fd);

  struct descriptor_archivo *opened_file = abrir_archivo(fd);
  struct file *temp_file = opened_file->tfiles;

  if (position < size){
    lock_acquire(&file_system_lock);
    file_seek(temp_file, position);
    lock_release(&file_system_lock);
  }
  else {
    exit(-1);
  }
}
//--------------SYS CALL TELL(filedescriptor)--------------
unsigned tell(int fd){
  struct descriptor_archivo *opened_file = abrir_archivo(fd);
  struct file *temp_file = opened_file->tfiles;
  
  lock_acquire(&file_system_lock);
  unsigned ret = file_tell(temp_file);
  lock_release(&file_system_lock);
  
  return ret;
}
//--------------SYS CALL CLOSE(filedescriptor)--------------
void close(int fd){
  struct descriptor_archivo *openfile = abrir_archivo(fd);
  if(openfile != NULL){
    lock_acquire(&file_system_lock);
    file_close(openfile->tfiles);
    lock_release(&file_system_lock);
    list_remove(&openfile->at);
    list_remove(&openfile->af);
    free(openfile);
  }
}