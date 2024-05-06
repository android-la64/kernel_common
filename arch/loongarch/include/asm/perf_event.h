/* SPDX-License-Identifier: GPL-2.0 */
/*
 * linux/arch/loongarch/include/asm/perf_event.h
 *
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __LOONGARCH_PERF_EVENT_H__
#define __LOONGARCH_PERF_EVENT_H__

#include <asm/ptrace.h>

#define perf_arch_bpf_user_pt_regs(regs) (struct user_pt_regs *)regs

#define perf_arch_fetch_caller_regs(regs, __ip) { \
	(regs)->csr_era = (__ip); \
	(regs)->regs[3] = (unsigned long) __builtin_frame_address(0); \
}

#endif /* __LOONGARCH_PERF_EVENT_H__ */
