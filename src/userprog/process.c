#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);



/* Starts a new thread running a user program loaded from
   `cmdline`. The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute (const char *file_name)
{
  /* Justin starts driving here. */
  char *fn_copy;
  char *name;
  char *save_ptr;
  tid_t tid;
  struct child_proc *cp = palloc_get_page(0);
  init_cp(cp);
  
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL) 
  {
    return TID_ERROR;
  }
  else
  {
    cp->file_name = fn_copy;
  }
  // copies files name into fn_copy
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Separate file name from file_name */
  name = palloc_get_page (0);
  if (name == NULL)
  {
    return TID_ERROR;
  }
  strlcpy (name, file_name, PGSIZE);
  // name is set to the first token of the file name
  name = strtok_r(name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  
  tid = thread_create (name, PRI_DEFAULT, start_process, cp);
  // set the tid of the child thread as the parent thread
  cp->tid = tid;
  if (tid == TID_ERROR) 
  {
    palloc_free_page (fn_copy);
  }
  //a semaphore was used to ensure the child process is initialized before we
  // 
  sema_down(&cp->start);

  if(!(cp->tid < 0)) 
  {
    list_push_back (&(thread_current()->children), &(cp->elem));
  }
  palloc_free_page (name);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process (void *cp)
{ 
  // Pranav starts driving here. 
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  // loads the child
  success = load ((char*) ((struct child_proc *) cp)->file_name, &if_.eip, 
    &if_.esp);

  if (!success) 
  {
    thread_exit();
  }
  
  // makes sure the current thread's child process is the one that was initialized
  thread_current()->cp = cp;
  thread_current()->cp->loaded = success ? 1 : -1;


  /* Awake child process to be fully initialized */
  // establishes the child process is loaded
  sema_up(&thread_current()->cp->load);
  sema_up(&thread_current()->cp->start);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
  // Pranav stop driving here. 
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait (tid_t child_tid)
{
  // waiting for the child_tid and once that's reached, we wait
  struct thread *current = thread_current();
  struct child_proc *cc; /* current child */
  struct child_proc *child = NULL;
  struct list_elem *c_elem = NULL;
  /* Abhijhit start driving. */

// iterating through the list of children in the current list
  for (struct list_elem *e = list_begin(&current->children); e != 
    list_end(&current->children); e = list_next(e)) 
  {
    cc = list_entry(e, struct child_proc, elem);
    // finding the match of the child tid
    if(cc->tid == child_tid) 
    { 
      child = cc;
      c_elem = e;
      break;
    }
  }
  /* if child process already has exited or is waiting, exit */
  if (c_elem == NULL || child == NULL || child->blocked) 
  {
    return -1;
  }
  // make child wait
  child->blocked = true;
  // if process exit hasn't been called, make the child wait
  if (!child->exit) 
  {
    sema_down(&(child->wait));
  }
  // remove the element from the list of children
  list_remove (c_elem);

// freeing the memory and returning child's exit status
  int retcode = child->exit_status;
  palloc_free_page(child);

  return retcode;
}

/* Free the current process's resources. */
void process_exit (void)
{
  /*  Justin starts driving. */
  struct thread *cur = thread_current ();
  uint32_t *pd;

// frees the child from the current list of children
  handle_children(cur, list_begin(&cur->children));
  // frees all files from the list of file descriptors
  handle_files(cur, list_begin(&cur->fds));

// resources have been freed, child is terminated
  sema_up (&cur->cp->wait);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}
/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack (void **esp, char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load (const char *file_name, void (**eip) (void), void **esp)
{
  /* Pranav starts driving. */
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  char *name = thread_current()->name;
  file = filesys_open (name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 3 || ehdr.e_version != 1 ||
      ehdr.e_phentsize != sizeof (struct Elf32_Phdr) || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
          case PT_NULL:
          case PT_NOTE:
          case PT_PHDR:
          case PT_STACK:
          default:
            /* Ignore this segment. */
            break;
          case PT_DYNAMIC:
          case PT_INTERP:
          case PT_SHLIB:
            goto done;
          case PT_LOAD:
            if (validate_segment (&phdr, file))
              {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0)
                  {
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes =
                        (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE) -
                        read_bytes); 
                  }
                else
                  {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                  }
                if (!load_segment (file, file_page, (void *) mem_page,
                                  read_bytes, zero_bytes, writable))
                  goto done;
              }
            else
              goto done;
            break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  /* Deny writes to executables. */
  // setting the current thread's executing file to the file we loaded
  file_deny_write (file);
  thread_current()->executing_file = file;
  /* Abhijit starts driving */
  success = true;

 done:
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack (void **esp, char *file_name)
{
  // Justin driving
  // use hex_dump to test stack
  uint8_t *kpage;
  bool success = false;
  
  // allocates a page into memory
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  // if oage is allocated successfully, it starts the stack pointer at PHYSBASE
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
      {
        *esp = PHYS_BASE;
      }
      else 
      {
        // if not then free page and stop setting up stack
        palloc_free_page (kpage);
        return false;
      }
    } 
    else {
      return false;
    }
    
  char *cmd_line[128];
  char *argv[128];
  int argc = 0;
  char *save_ptr;
  char *delim = " ";
  char *token = strtok_r(file_name, delim, &save_ptr);
  // tokenizing the command line
  while (token != NULL) 
  {
    cmd_line[argc++] = token;
    token = strtok_r(NULL, delim, &save_ptr);
  }
  // maybe make a single pointer, suggested by piazza
  // make a copy of the stack pointer so that main one isn't altered
  char *my_esp = (char *)*esp;
  int i;
  // pushing the tokens into the stack
  for (i = 0; i < argc; i++) 
  {
    my_esp -= strlen(cmd_line[i]) + 1;
    if (my_esp < ((char *)PHYS_BASE - PGSIZE)) 
    {
      return false;
    }
    memcpy((void *)my_esp, (void *) cmd_line[i], strlen(cmd_line[i]) + 1);
    // copies addresses of tokens into argv
    argv[i] = my_esp;
  }
  // assignment page said to do null terminal
  argv[argc] = NULL;
  // word align
  // align the stack pointer
  while ((int) my_esp % 4 != 0)
  {
    my_esp--;
    if (my_esp < (char *)PHYS_BASE - PGSIZE) 
    {
      return false;
    }
  }

  // push addresses of strings + null pointer sentinel into the stack
  for (i = argc; i >= 0; i--) 
  {
    my_esp -= 4;
    if (my_esp < (char *)PHYS_BASE - PGSIZE) 
    {
      return false;
    }
    // copies argv into the stack
    memcpy(my_esp, &argv[i], 4);  
  }

  // push argv
  // push address of argv into stack
  char **temp = my_esp;
  my_esp -= 4;
  
  // memcpy(my_esp, temp, 4);
  *((char **)my_esp) = temp;
  
  if (my_esp < (char *)PHYS_BASE - PGSIZE) 
  {
    return false;
  }
 /* Abhijit driving */
  // push argc
  // push address of argc into stack
  my_esp -= 4;
  if (my_esp < (char *)PHYS_BASE - PGSIZE) 
  {
    return false;
  }
  memcpy(my_esp, &argc, 4);

  // push fake "return address"
  my_esp -= 4;
  // checks to see if stack pointer is in user space
  if (my_esp < (char *)PHYS_BASE - PGSIZE) 
  {
    return false;
  }
  memcpy(my_esp, &argv[argc], 4);
  *esp = my_esp;
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL &&
          pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Student helper functions */

/* Pranav driving */
/* Removes all children from current thread's list of children and frees
   the child if it has exited. */
void handle_children (struct thread *cur, struct list_elem *e)
{
  struct child_proc *cc;
  for (; !list_empty(&cur->children); e = list_begin(&cur->children)) 
  {
    list_remove(e);
    cc = list_entry(e, struct child_proc, elem);
    if (cc->exit == true) 
    {
      palloc_free_page (cc);
    } 
  }
}

/* Removes all file_ds from current thread's list of file descriptors and close
   current thread's executing file if valid. */
void handle_files (struct thread *cur, struct list_elem *e)
{
  if(cur->executing_file != NULL) {
    file_allow_write(cur->executing_file);
    file_close(cur->executing_file);
  }
  for (; !list_empty(&cur->fds); e = list_begin(&cur->fds)) 
  {
    list_remove(e);
    struct file_d *desc = list_entry(e, struct file_d, elem);
    list_remove(&desc->elem);
    file_close(desc->file);
    palloc_free_page(desc);
  }
}

/* initialize fields of child_proc struct */
void init_cp(struct child_proc* cp)
{
  cp->blocked = 0;
  cp->exit = 0;
  cp->exit_status = -1;
  cp->loaded = 0;
  sema_init(&cp->start, 0);
  sema_init(&cp->wait, 0);
  sema_init(&cp->load, 0);
}