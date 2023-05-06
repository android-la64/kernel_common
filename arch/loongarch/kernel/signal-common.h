/* SPDX-License-Identifier: GPL-2.0+ */
/*
* Copyright (C) 2020 Loongson Technology Corporation Limited
*
* Author: Hanlu Li <lihanlu@loongson.cn>
*/

#ifndef __SIGNAL_COMMON_H
#define __SIGNAL_COMMON_H

/* #define DEBUG_SIG */

#ifdef DEBUG_SIG
#  define DEBUGP(fmt, args...) printk("%s: " fmt, __func__, ##args)
#else
#  define DEBUGP(fmt, args...)
#endif

/*
 * Determine which stack to use..
 */
extern void __user *get_sigframe(struct ksignal *ksig, struct pt_regs *regs,
				 size_t frame_size);
/* Check and clear pending FPU exceptions in saved CSR */
extern int fcsr_pending(unsigned int __user *fcsr);

/* Make sure we will not lose FPU ownership */
#define lock_fpu_owner()	({ preempt_disable(); pagefault_disable(); })
#define unlock_fpu_owner()	({ pagefault_enable(); preempt_enable(); })

#endif	/* __SIGNAL_COMMON_H */
