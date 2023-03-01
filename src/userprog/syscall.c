#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "list.h"
#include "lib/kernel/console.h"


static void syscall_handler (struct intr_frame *);

struct lock file_lock;

struct file_d
{
  int fd;
  struct file *f;
  struct list_elem elem;
};

/* Student helper functions */
void terminate_process(int status);
void *valid_addr(const void *vaddr);
struct file_d *search_list(struct list *files, int fd);

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}


static void syscall_handler (struct intr_frame *f UNUSED)
{
  printf ("system call!\n");
  int *my_esp = f->esp;
  valid_addr(my_esp);
  int syscall_code = *my_esp;
  switch (syscall_code)
  {
    case SYS_HALT:
    {
      shutdown_power_off();
      break;
    }
    case SYS_EXIT:
    {
      valid_addr(my_esp + 1);
      terminate_process(*(my_esp + 1));
      break;
    }
    case SYS_EXEC:
    {
      valid_addr(my_esp + 1);
      char *file_name = (*(my_esp + 1));
      f->eax = process_execute(file_name);
      break;
    }
    case SYS_WAIT:
    {
      valid_addr(my_esp + 1);
      f->eax = process_wait(*(my_esp + 1));
      break;
    }
    case SYS_CREATE:
    {
      valid_addr(my_esp + 1);
      valid_addr(my_esp + 2);
      char *file_name = *(my_esp + 1);
      int intial_size = *(my_esp + 2);
      lock_acquire(&file_lock);
      f->eax = filesys_create(file_name, intial_size);
      lock_release(&file_lock);
      break;
    }
    case SYS_REMOVE:
    {
      valid_addr(*(my_esp + 1));
      char *file_name = *(my_esp + 1);
      lock_acquire(&file_lock);
      f->eax = filesys_remove(file_name);
      lock_release(&file_lock);
      break;
    }
    case SYS_OPEN:
    {
      valid_addr(*(my_esp + 1));
      char *file_name = *(my_esp + 1);
      lock_acquire(&file_lock);
      struct file *file = filesys_open(file_name);
      lock_release(&file_lock);
      struct thread *current = thread_current();
      if (f != NULL)
      {
        struct file_d *f_desc = palloc_get_page(0);
        if (f_desc == NULL)
        {
          return TID_ERROR;
        }
        f_desc->f = file;
        f_desc->fd = current->num_fd;
        current->num_fd++;
        list_push_back(&current->file_ds, &f_desc->elem);
        f->eax = f_desc->fd;
      }
      else
      {
        f->eax = -1;
      }
      break;
    }
    case SYS_FILESIZE:
    {
      valid_addr(my_esp + 1);
      int fd = *(my_esp + 1);
      lock_acquire(&file_lock);
      struct file_d *f_desc = search_list(&(thread_current()->file_ds), fd);
      f->eax = file_length(f_desc->f);
      lock_release(&file_lock);
      break;
    }
    case SYS_READ:
    {
      // not implemented
      break;
    }
    case SYS_WRITE:
    {
      // not implemented
      break;
    }
    case SYS_SEEK:
    {
      valid_addr(my_esp + 1);
      lock_acquire(&file_lock);
      struct file_d *f_desc = search_list(&thread_current()->file_ds,
        *(my_esp + 1));
      file_seek(f_desc->f, *(my_esp + 2));
      lock_release(&file_lock);
      break;
    }
    case SYS_TELL:
    {
      valid_addr(my_esp + 1);
      lock_acquire(&file_lock);
      struct file_d *f_desc = search_list(&thread_current()->file_ds,
        *(my_esp + 1));
      f->eax = file_tell(f_desc->f);
      lock_release(&file_lock);
      break;
    }
    case SYS_CLOSE:
    {
      // not implemented
      break;
    }
    default:
    {
      
      terminate_process(-1);
      break;
    }
  }
}

void terminate_process(int status)
{
  struct thread *current = thread_current();
  current->exit_status = status;
  struct child_proc *cc;
  struct child_proc *child = NULL;
  for (struct list_elem *e = list_begin(&current->children); e != list_end(&current->children);
    e = list_next(e))
    {
      cc = list_entry(e, struct child_proc, elem);
      if (current->tid == cc->tid)
      {
        child = cc;
        child->exit_status = status;
        child->alive = 0;
      }
    }
    if (child != NULL)
    {
      if (current->parent->tid == current->tid)
      {
        sema_up(&child->wait);
      }
    }
    thread_exit();
}

void *valid_addr(const void *vaddr)
{
  void *esp = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!is_user_vaddr(vaddr) || esp == NULL)
  {
    terminate_process(-1);
    return 0;
  }
  return esp;
}


struct file_d *search_list(struct list *files, int fd)
{
  struct list_elem *e;
  for (e = list_begin (&files); e != list_end (&files);
       e = list_next (e))
    {
      struct file_d *f = list_entry(e, struct file_d, elem);
      if (f->fd == fd)
      {
        return f;
      }
    }
    return NULL;
}
