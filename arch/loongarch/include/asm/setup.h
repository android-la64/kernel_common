/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */

#ifndef _LOONGARCH_SETUP_H
#define _LOONGARCH_SETUP_H

#include <linux/types.h>
#include <linux/threads.h>
#include <uapi/asm/setup.h>

#define VECSIZE 0x200

extern unsigned long eentry;
extern unsigned long tlbrentry;
extern unsigned long pcpu_handlers[NR_CPUS];
extern long exception_handlers[VECSIZE * 128 / sizeof(long)];
extern void tlb_init(int cpu);
extern void cpu_cache_init(void);
extern void cache_error_setup(void);
extern void per_cpu_trap_init(int cpu);
extern void set_handler(unsigned long offset, void *addr, unsigned long len);
extern void set_merr_handler(unsigned long offset, void *addr, unsigned long len);

#endif /* __SETUP_H */
