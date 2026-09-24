// SPDX-License-Identifier: GPL-2.0
/*
 * crc32.c - CRC32 and CRC32C using LoongArch crc* instructions
 */

#include <linux/crc32.h>
#include <linux/jump_label.h>
#include <crypto/internal/hash.h>

#include <asm/cpu-features.h>
#include <asm/unaligned.h>

static DEFINE_STATIC_KEY_FALSE(have_ual);
static DEFINE_STATIC_KEY_FALSE(have_crc32);

extern u32 __pure crc32_le_base(u32 crc, unsigned char const *p, size_t len);
extern u32 __pure __crc32c_le_base(u32 crc, unsigned char const *p, size_t len);

#define CRC3WAY_STRIDE	SZ_2K
#define CRC3WAY_BLOCK	(3 * CRC3WAY_STRIDE)

#define _CRC32(crc, value, size, type)			\
do {							\
	__asm__ __volatile__(				\
		#type ".w." #size ".w" " %0, %1, %0\n\t"\
		: "+r" (crc)				\
		: "r" (value)				\
		: "memory");				\
} while (0)

#define CRC32(crc, value, size)		_CRC32(crc, value, size, crc)
#define CRC32C(crc, value, size)	_CRC32(crc, value, size, crcc)

static u32 crc32_k1tab[4][256], crc32_k2tab[4][256];
static u32 crc32c_k1tab[4][256], crc32c_k2tab[4][256];

static void crc3way_build_table(u32 tab[4][256],
		u32 (*shift)(u32, size_t), size_t len)
{
	int i, j;

	for (i = 0; i < 4; i++)
		for (j = 0; j < 256; j++)
			tab[i][j] = shift((u32)j << (8 * i), len);
}

static void crc3way_table_init(void)
{
	crc3way_build_table(crc32_k1tab, crc32_le_shift, CRC3WAY_STRIDE);
	crc3way_build_table(crc32_k2tab, crc32_le_shift, 2 * CRC3WAY_STRIDE);
	crc3way_build_table(crc32c_k1tab, __crc32c_le_shift, CRC3WAY_STRIDE);
	crc3way_build_table(crc32c_k2tab, __crc32c_le_shift, 2 * CRC3WAY_STRIDE);
}

static inline u32 crc3way_shift(const u32 tab[4][256], u32 crc)
{
	return tab[0][crc & 0xff] ^ tab[1][(crc >> 8) & 0xff] ^
	       tab[2][(crc >> 16) & 0xff] ^ tab[3][crc >> 24];
}

#define CRC3WAY_LOOP(crc, p, len, type, k1tab, k2tab)			\
while ((len) >= CRC3WAY_BLOCK) {					\
	unsigned int i;							\
	u32 c0 = (crc), c1 = 0, c2 = 0;					\
	const u8 *p1 = (p) + CRC3WAY_STRIDE;				\
	const u8 *p2 = (p) + 2 * CRC3WAY_STRIDE;			\
									\
	for (i = 0; i < CRC3WAY_STRIDE; i += sizeof(u64)) {		\
		_CRC32(c0, get_le64((p) + i), d, type);			\
		_CRC32(c1, get_le64((p1) + i), d, type);		\
		_CRC32(c2, get_le64((p2) + i), d, type);		\
	}								\
	(p) += CRC3WAY_BLOCK; (len) -= CRC3WAY_BLOCK;			\
	crc = crc3way_shift(k2tab, c0) ^ crc3way_shift(k1tab, c1) ^ c2;	\
}

static inline u16 get_le16(const void *p)
{
	if (static_branch_likely(&have_ual))
		return *((__le16 *)p);
	else
		return get_unaligned_le16(p);
}

static inline u32 get_le32(const void *p)
{
	if (static_branch_likely(&have_ual))
		return *((__le32 *)p);
	else
		return get_unaligned_le32(p);
}

static inline u64 get_le64(const void *p)
{
	if (static_branch_likely(&have_ual))
		return *((__le64 *)p);
	else
		return get_unaligned_le64(p);
}

u32 __pure crc32_le(u32 crc_, unsigned char const *p, size_t len)
{
	u32 crc = crc_;

	if (!static_branch_likely(&have_crc32))
		return crc32_le_base(crc, p, len);

	CRC3WAY_LOOP(crc, p, len, crc, crc32_k1tab, crc32_k2tab);

	while (len >= sizeof(u64)) {
		u64 value = get_le64(p);

		CRC32(crc, value, d);
		p += sizeof(u64);
		len -= sizeof(u64);
	}

	if (len & sizeof(u32)) {
		u32 value = get_le32(p);

		CRC32(crc, value, w);
		p += sizeof(u32);
	}

	if (len & sizeof(u16)) {
		u16 value = get_le16(p);

		CRC32(crc, value, h);
		p += sizeof(u16);
	}

	if (len & sizeof(u8)) {
		u8 value = *p++;

		CRC32(crc, value, b);
	}

	return crc;
}

u32 __pure __crc32c_le(u32 crc_, unsigned char const *p, size_t len)
{
	u32 crc = crc_;

	if (!static_branch_likely(&have_crc32))
		return __crc32c_le_base(crc, p, len);

	CRC3WAY_LOOP(crc, p, len, crcc, crc32c_k1tab, crc32c_k2tab);

	while (len >= sizeof(u64)) {
		u64 value = get_le64(p);

		CRC32C(crc, value, d);
		p += sizeof(u64);
		len -= sizeof(u64);
	}

	if (len & sizeof(u32)) {
		u32 value = get_le32(p);

		CRC32C(crc, value, w);
		p += sizeof(u32);
	}

	if (len & sizeof(u16)) {
		u16 value = get_le16(p);

		CRC32C(crc, value, h);
		p += sizeof(u16);
	}

	if (len & sizeof(u8)) {
		u8 value = *p++;

		CRC32C(crc, value, b);
	}

	return crc;
}

static int __init crc32_mod_init(void)
{
	crc3way_table_init();

	if (cpu_has_ual)
		static_branch_enable(&have_ual);
	if (cpu_has_crc32)
		static_branch_enable(&have_crc32);
	return 0;
}
subsys_initcall(crc32_mod_init);
