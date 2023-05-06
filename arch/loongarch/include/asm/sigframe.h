/* SPDX-License-Identifier: GPL-2.0+ */

#include <asm/siginfo.h>
#include <asm/ucontext.h>

struct rt_sigframe {
	u32 rs_ass[4];		/* argument save space for o32 */
	u32 rs_pad[2];		/* Was: signal trampoline */
	struct siginfo rs_info;
	struct ucontext rs_uctx;
};
