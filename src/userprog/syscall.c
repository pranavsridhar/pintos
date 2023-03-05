#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"

static void syscall_handler (struct intr_frame *);

static int32_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

/* Student helper functions */
bool valid_addr (const void *);
struct file_d *search_list(struct thread *, int fd);
void exit (int);
struct child_proc *search_child(int tid);

struct lock file_lock;

void syscall_init (void)
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void syscall_handler (struct intr_frame *f)
{
  int *my_esp;
  my_esp = f->esp;
  for (int i = 0; i < 4; i++)
  { 
    if (!valid_addr(my_esp + i))
    {
      exit (-1);
    }
  }
  /* Justin driving */ 
  int exit_status;
  char *cmdline;
  char *filename;
  tid_t tid;
  unsigned initial_size;
  char *file; 
  int fd;
  void *buffer;    
  unsigned size;
  unsigned position;
  int retcode; 
  struct file_d *file_d;
  int syscall_number = *my_esp;
  int cur_fd; /* 0 == STDIN_FILENO, 1 == STDOUT_FILENO */
  int start_fd = 2;
  switch (syscall_number)
    {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      exit_status = *(my_esp + 1);
      exit(exit_status);
      break;
    case SYS_EXEC:
      cmdline = (char *) *(my_esp + 1);
      get_user((const uint8_t*) cmdline) == -1 ? exit(-1) : NULL; 
      lock_acquire(&file_lock);
      tid_t tid = process_execute(cmdline);
      struct child_proc *cp = search_child(tid);
      if (cp->loaded == 0)
      {
        sema_down(&cp->load);
      }
      if (cp->loaded == -1)
      {
        list_remove(&cp->elem);
        free(cp);
      }
      lock_release(&file_lock);
      f->eax = tid;
      break;
    case SYS_WAIT:
      tid = *(my_esp + 1);
      f->eax = process_wait(tid);
      break;
    /* Abhijit driving */
    case SYS_CREATE:
      filename = (char *) *(my_esp + 1);
      initial_size = *(my_esp + 2);
      get_user((const uint8_t*) filename) == -1 ? exit(-1) : NULL; 
      lock_acquire(&file_lock);
      f->eax = filesys_create(filename, initial_size);
      lock_release(&file_lock);
      break;
    case SYS_REMOVE:
      filename = (char *) *(my_esp + 1);
      get_user((const uint8_t*) filename) == -1 ? exit(-1) : NULL;
      lock_acquire(&file_lock);
      f->eax = filesys_remove(filename);
      lock_release(&file_lock);
      break;
    case SYS_OPEN:
      file = (char *) *(my_esp + 1);
      get_user((const uint8_t*) file) == -1 ? exit(-1) : NULL;
      lock_acquire(&file_lock);
      struct file* file_opened;
      struct file_d *fd = palloc_get_page(0);
      if (fd != NULL) 
      {
        file_opened = filesys_open(file);
        if (!file_opened) 
        {
          palloc_free_page (fd);
          fd->fid = -1;
        }
        else 
        {
          fd->file = file_opened; 
          struct list *fd_list = &thread_current()->fds;
          if (!list_empty(fd_list))
          {
            cur_fd = (list_entry(list_back(fd_list), struct file_d, elem)->fid)
               + 1;
            fd->fid = cur_fd;
          }
          else 
          {
            fd->fid = start_fd;
          }
          list_push_back(fd_list, &(fd->elem));
        }
      }
      else 
      {
        fd->fid = -1;
      }
      lock_release(&file_lock);
      f->eax = fd->fid;
      break;
    case SYS_FILESIZE:
      fd = *(my_esp + 1);
      lock_acquire(&file_lock);
      file_d = search_list(thread_current(), fd);
      if(file_d == NULL) 
      {
        return -1;
      }
      retcode = file_length(file_d->file);
      lock_release(&file_lock);
      f->eax = retcode;
      break;
    case SYS_READ:
      fd = *(my_esp + 1);
      buffer = (void *) *(my_esp + 2);
      size = *(my_esp + 3);
      get_user((const uint8_t*) buffer) == -1 ? exit(-1) : NULL;
      get_user((const uint8_t*) buffer + size) == -1 ? exit(-1)
        : NULL;
      lock_acquire(&file_lock);
      char *my_buffer = (char *)buffer; 
      retcode = -1;
      if(fd == 0) 
      { 
        for(int i = 0; i < size; i++) 
        {
          if(!put_user(my_buffer + i, input_getc()) )
            exit(-1); 
        }
        retcode = size;
      }
      else 
      {
        file_d = search_list(thread_current(), fd);
        if (file_d && file_d->file) 
        {
          retcode = file_read(file_d->file, buffer, size);
        }
      }
      lock_release(&file_lock);
      f->eax = retcode;
      break;
    /* Pranav driving */
    case SYS_WRITE:
      fd = *(my_esp + 1);
      buffer = (void *) *(my_esp + 2);
      size = *(my_esp + 3);
      get_user((const uint8_t*) buffer) == -1 ? exit(-1) : NULL;
      get_user((const uint8_t*) buffer + size) == -1 ? exit(-1)
        : NULL;
      lock_acquire(&file_lock);
      retcode = -1;
      if(fd == 1) 
      { 
        putbuf(buffer, size);
        retcode = size;
      }
      else 
      {
        file_d = search_list(thread_current(), fd);
        if (file_d && file_d->file) 
        {
          retcode = file_write(file_d->file, buffer, size);
        }
      }
      lock_release(&file_lock);
      f->eax = retcode;
      break;
    case SYS_SEEK:
      fd = *(my_esp + 1);
      position = *(my_esp + 2);
      lock_acquire(&file_lock);
      file_d = search_list(thread_current(), fd);
      if(file_d && file_d->file) 
      {
        file_seek(file_d->file, position);
      }
      lock_release(&file_lock);
      break;
    case SYS_TELL:
      fd = *(my_esp + 1);
      /* Justin driving */
      lock_acquire(&file_lock);
      file_d = search_list(thread_current(), fd);
      retcode = (file_d && file_d->file) ? file_tell(file_d->file) : -1;
      lock_release(&file_lock);
      f->eax = retcode;
      break;
    case SYS_CLOSE:
      fd = *(my_esp + 1);
      lock_acquire(&file_lock);
      file_d = search_list(thread_current(), fd);
      if (file_d != NULL && file_d->file) 
      {
        file_close(file_d->file);
        list_remove(&(file_d->elem));
        palloc_free_page(file_d);
      }
      lock_release(&file_lock);
      break;
    default:
      exit(-1);
      break;
    }
    
}

/* Abhijit driving */
/* Student helper functions */
void exit(int status) 
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  struct child_proc *cp = thread_current()->cp;
  if(cp != NULL) 
  {
    cp->exit = 1;
    cp->exit_status = status;
  }
  thread_exit();
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int32_t get_user (const uint8_t *uaddr) 
{
  /* check uaddr below PHYS_BASE */
  if (is_user_vaddr(uaddr))
  {
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (result) : "m" (*uaddr));
    return result;
  }
  return -1;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool put_user (uint8_t *udst, uint8_t byte) 
{
  /* check udst below PHYS_BASE */
  if (is_user_vaddr(udst))
  {
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
  }
  return -1;
}

struct file_d *search_list(struct thread *t, int fd)
{
  ASSERT (t != NULL);

  if (list_empty(&t->fds) || fd < 2) {
    return NULL;
  }

  struct list_elem *e;

    for(e = list_begin(&t->fds);
        e != list_end(&t->fds); e = list_next(e))
    {
      struct file_d *desc = list_entry(e, struct file_d, elem);
      if(desc->fid == fd) {
        return desc;
      }
    }

  return NULL;
}

/* Pranav driving */
struct child_proc *search_child(int tid)
{
  struct thread *t = thread_current();
  struct list_elem *e;

    for(e = list_begin(&t->children);
        e != list_end(&t->children); e = list_next(e))
    {
      struct child_proc *cp = list_entry(e, struct child_proc, elem);
      if(cp->tid == tid) {
        return cp;
      }
    }

  return NULL; 
}

bool valid_addr (const void *usr_ptr)
{
  struct thread *cur = thread_current ();
  if (usr_ptr != NULL && is_user_vaddr (usr_ptr))
    {
      return (pagedir_get_page (cur->pagedir, usr_ptr)) != NULL;
    }
  return false;
}

void file_lock_acquire()
{
  lock_acquire(&file_lock);
}

void file_lock_release()
{
  lock_release(&file_lock);
}