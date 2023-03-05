#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/process.h"

void syscall_init (void);

void exit (int);

/* File descriptor */
struct file_d
{
  int fid;
  struct list_elem elem;
  struct file* file;
};

#endif /* userprog/syscall.h */