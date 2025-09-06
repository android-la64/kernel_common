/* SPDX-License-Identifier: GPL-2.0 */
/*
 * LoongArch specific ACPICA environments and implementation
 *
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 * Author: lvjianmin <lvjianmin@loongson.cn>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _ASM_LOONGARCH_ACENV_H
#define _ASM_LOONGARCH_ACENV_H

#ifdef CONFIG_ARCH_STRICT_ALIGN
#define ACPI_MISALIGNMENT_NOT_SUPPORTED
#endif /* CONFIG_ARCH_STRICT_ALIGN */

#endif /* _ASM_LOONGARCH_ACENV_H */
