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
#include "devices/input.h"
#include "devices/shutdown.h"

#define STDIN_FILENO 0
#define STDOUT_FILENO 1

static void syscall_handler (struct intr_frame *);
static bool verificar_puntero(void *pointer); 
void delete_children(struct hash_elem *elem, void *aux);

void delete_parent_from_child(struct hash_elem *elem, void *aux);
static struct lock file_system_lock;

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

  if (!verificar_puntero(f->esp))
  {
    exit(-1);
  }

  switch (*(int*)f->esp){
    case SYS_HALT:
      shutdown_power_off();
      break;

    // *************************************************************************************************************************************************
    case SYS_EXIT:
      if (!verificar_puntero((int*)f->esp + 1))
        exit(-1);
      status = *((int*)f->esp + 1);
      
      exit(status);
      break;

    // *************************************************************************************************************************************************
    case SYS_EXEC:
      cmd_name = (char*)(*((int*)f->esp + 1)); 
      if (!verificar_puntero(cmd_name))
        exit(-1);

      f->eax = exec(cmd_name);
      break;

    // *************************************************************************************************************************************************
    case SYS_WAIT:
      if (!verificar_puntero((int*)f->esp + 1))
        exit(-1);
      
      tid = *((int*)f->esp + 1); 
      f->eax = wait(tid);
      break;

    // *************************************************************************************************************************************************
    case SYS_READ:
      if (!verificar_puntero((int*)f->esp + 1))
        exit(-1);

      if (!verificar_puntero((int*)f->esp + 3))
        exit(-1);

      fd = (*((int*)f->esp + 1)); 
      buffer = (char*)(*((int*)f->esp + 2));
      size = (*((int*)f->esp + 3));

      if (!verificar_puntero(buffer))
        exit(-1);
      
      f->eax = read(fd, buffer, size);
      break;

    // *************************************************************************************************************************************************
    case SYS_REMOVE:
      file_name = (char*)(*((int*)f->esp + 1)); 
      if (!verificar_puntero(file_name))
        exit(-1);
      
      f->eax = remove(file_name);
      break;

    // *************************************************************************************************************************************************
    case SYS_OPEN:
      file_name = (void*)(*((int*)f->esp + 1)); 
      if (!verificar_puntero(file_name))
        exit(-1);
      
      f->eax = open(file_name);
      break;

    // *************************************************************************************************************************************************
    case SYS_FILESIZE:
      if (!verificar_puntero((int*)f->esp + 1))
        exit(-1);
      
      fd = (*((int*)f->esp + 1)); 
      f->eax = filesize(fd);
      break;

    // *************************************************************************************************************************************************
    case SYS_CREATE: 
      if (!verificar_puntero((int*)f->esp + 1))
        exit(-1);
      
      if (!verificar_puntero((int*)f->esp + 2))
        exit(-1);
      
      file_name = (char*)(*((int*)f->esp + 1)); 
      if (!verificar_puntero(file_name))
        exit(-1);

      size = (*((int*)f->esp + 2));
      f->eax = create(file_name, size);
      break;

    // *************************************************************************************************************************************************
    case SYS_WRITE:
      if (!verificar_puntero((int*)f->esp + 1))
        exit(-1);

      if (!verificar_puntero((int*)f->esp + 3))
        exit(-1);

      fd = *((int*)f->esp + 1);
      buffer = (void*)(*((int*)f->esp + 2));
      size = *((int*)f->esp + 3);

      if (!verificar_puntero(buffer))
        exit(-1);
      f->eax = write(fd, buffer, size);
      break;

    // *************************************************************************************************************************************************
    case SYS_SEEK:
      if (!verificar_puntero((int*)f->esp + 1))
        exit(-1);
      
      if (!verificar_puntero((int*)f->esp + 2))
        exit(-1);
          
      fd = *((int*)f->esp + 1);
      position = *((int*)f->esp + 2);

      seek(fd, position);
      break;

    // *************************************************************************************************************************************************
    case SYS_TELL:
      if (!verificar_puntero((int*)f->esp + 1))
        exit(-1);

      fd = *((int*)f->esp + 1);

      f->eax = tell(fd);
      break;

    // *************************************************************************************************************************************************
    case SYS_CLOSE:
      if (!verificar_puntero((int*)f->esp + 1))
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

//Función para validar puntero
bool 
verificar_puntero(void *pointer)
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
      struct descriptor_archivo *opfile  = list_entry(files, struct descriptor_archivo, archivos_thread);
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
/*void halt (void) {
  shutdown_power_off();
}*/

//--------------SYS CALL EXIT()--------------
void exit(int status) {
  struct thread *cur = thread_current();
  // Process termination message. 
  printf("%s: exit(%d)\n", cur->name, status);
  
  struct thread *parent = get_thread(cur->padre);
  if (parent)
  {
    struct children_process child;
    child.pid = cur->tid;
    struct children_process *child_control = hash_entry(hash_find(&parent->children, &child.elem), struct children_process, elem);
    if (child_control){
      lock_acquire(&parent->wait_lock);
      child_control->finish = true; 
      child_control->status = status;
      cond_signal(&parent->wait_cond, &parent->wait_lock);
      lock_release(&parent->wait_lock);
    }
  }
  
  hash_apply(&cur->children, delete_parent_from_child);
  hash_destroy(&cur->children, delete_children);

  struct lock *lock;
  while (!list_empty(&cur->locks))
  {
    lock = list_entry(list_pop_back(&cur->locks), struct lock, elem);
    lock_release(lock);
  }

  if (cur->fd_exec != -1)
    close(cur->fd_exec);

  struct list_elem *iter = list_begin(&cur->files); 
  while (!list_empty(&cur->files))
  {   
    struct descriptor_archivo *op_file = list_entry(iter, struct descriptor_archivo, archivos_thread);
    iter = list_next(iter);
    close(op_file->fd);
  }
  
  thread_exit();
}

//--------------SYS CALL EXECUTE()--------------
pid_t exec(const char* cmd_line){
  tid_t child;
  struct thread *cur = thread_current();
  struct children_process *child_p = NULL;
  cur->hijo_correctamente_cargado = false;
  cur->hijo_esperando_proceso = false;
  
  child = process_execute(cmd_line);
  
  if (child != -1) {
    child_p = malloc(sizeof(struct children_process));
    child_p->pid = child;
    child_p->status = -1;
    child_p->finish = false; 
    child_p->parent_waited = false;
    hash_insert(&cur->children, &child_p->elem);
  }
  else{
    return TID_ERROR;
  }
  
  if(!cur->hijo_correctamente_cargado)
    sema_down(&cur->exec_sema);

  if (!cur->hijo_esperando_proceso){
    hash_delete(&cur->children,&child_p->elem);
    free(child_p);
    child = -1;
  }

  return child;
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
  struct thread *cur = thread_current();
  struct file *last_file = NULL;
  struct file *file_op = NULL;

  struct list_elem *iter = list_begin(&lista_archivos);
  while (iter != list_end(&lista_archivos))
  {
    struct descriptor_archivo *op_file = list_entry(iter, struct descriptor_archivo, archivos_filesystem);
    if (strcmp(file, op_file->id_archivo) == 0){
      last_file = op_file->tfiles;
      break;
    }
    iter = list_next(iter);
  }
  
  lock_acquire(&file_system_lock);
  if (last_file != NULL)
    file_op = file_reopen(last_file);
  else 
    file_op = filesys_open(file);
  lock_release(&file_system_lock);
  
  if(file_op != NULL){
    struct descriptor_archivo *op_file = malloc(sizeof(struct descriptor_archivo));
    op_file->fd = cur->fd_next++;
    op_file->tfiles = file_op;
    op_file->id_archivo = (char*)file;
    list_push_back(&cur->files, &op_file->archivos_thread);
    list_push_back(&lista_archivos, &op_file->archivos_filesystem);
    return op_file->fd;
  }
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
  int read_size = -1;

  if (fd){    
    struct descriptor_archivo *opened_file = abrir_archivo(fd);
    if (opened_file != NULL){
      intr_disable();
      lock_acquire(&file_system_lock);
      struct file * temp_file = opened_file->tfiles;
      read_size = file_read(temp_file, buffer, size);
      lock_release(&file_system_lock);
      intr_enable();
    }
  }
  else {
    int i = 0;
    while((unsigned int)i < size)
      buffer[i++] = input_getc();
    read_size = size;
  }
  return read_size;
}
//--------------SYS CALL WRITE(filedescriptor, buffer, size)--------------
int write (int fd, void* buffer, unsigned size){
  
  if (fd == STDIN_FILENO){
    return 0;
  }
  else if(fd == STDOUT_FILENO){
    putbuf((char*)buffer, size);
    return size;
  }
  else{
    struct descriptor_archivo *archivo_abierto = abrir_archivo(fd);
    int bytes_escritos = 0;

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

  struct descriptor_archivo *archivo_abierto = abrir_archivo(fd);
  struct file *archivo = archivo_abierto->tfiles;

  if (position < (unsigned int)size){
    lock_acquire(&file_system_lock);
    file_seek(archivo, position);
    lock_release(&file_system_lock);
  }
  else {
    exit(-1);
  }
}
//--------------SYS CALL TELL(filedescriptor)--------------
unsigned tell(int fd){
  struct descriptor_archivo *archivo = abrir_archivo(fd);
  struct file *lector_tell = archivo->tfiles;
  
  if(archivo == NULL){
    lock_release(&file_system_lock);
    return -1;
  }
  lock_acquire(&file_system_lock);
  unsigned status = file_tell(lector_tell);
  lock_release(&file_system_lock);
  
  return status;
}
//--------------SYS CALL CLOSE(filedescriptor)--------------
void close(int fd){
  struct descriptor_archivo *archivo = abrir_archivo(fd);
  if(archivo != NULL){
    lock_acquire(&file_system_lock);
    file_close(archivo->tfiles);
    lock_release(&file_system_lock);
    list_remove(&archivo->archivos_thread);
    list_remove(&archivo->archivos_filesystem);
    free(archivo);
  }
}
