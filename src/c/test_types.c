/* $Id: test_types.c 154 2010-04-26 17:00:24Z tp $ */
/*
 * Unit tests for the basic integer types and functions for encoding and
 * decoding such integer types to and from byte streams.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stdio.h>
#include <string.h>
#include "sph_types.h"
#include "utest.h"

static void
test_config(void)
{
#ifdef SPH_UPTR
	ASSERT(sizeof(void *) == sizeof(SPH_UPTR));
#endif
	ASSERT(sizeof(sph_u32) >= 4);
	ASSERT((((sph_u32)-1) >> 31) >= 1U);
#ifdef SPH_64
	ASSERT(sizeof(sph_u64) >= 8);
	ASSERT((((sph_u64)-1) >> 63) >= 1U);
#endif
}

static void
test_types32(void)
{
	unsigned i;
	union {
		unsigned char bytes[64];
		sph_u32 v32;
	} u;

#if defined SPH_LITTLE_ENDIAN || defined SPH_BIG_ENDIAN
	ASSERT(sizeof(sph_u32) == 4);
#else
	ASSERT(sizeof(sph_u32) >= 4);
#endif

	for (i = 0; i < sizeof u.bytes; i ++)
		u.bytes[i] = i;
	for (i = 0; (i + 3) < sizeof u.bytes; i ++) {
		sph_u32 v, w;

		v = ((sph_u32)i << 24)
			| ((sph_u32)(i + 1) << 16)
			| ((sph_u32)(i + 2) << 8)
			| (sph_u32)(i + 3);
		w = ((sph_u32)(i + 3) << 24)
			| ((sph_u32)(i + 2) << 16)
			| ((sph_u32)(i + 1) << 8)
			| (sph_u32)i;
		ASSERT(sph_dec32be(u.bytes + i) == v);
		ASSERT(sph_dec32le(u.bytes + i) == w);
		if (i % 4 == 0) {
			ASSERT(sph_dec32be_aligned(u.bytes + i) == v);
			ASSERT(sph_dec32le_aligned(u.bytes + i) == w);
		}
	}
	memset(u.bytes, 0, sizeof u.bytes);
	for (i = 0; (i + 3) < sizeof u.bytes; i ++) {
		sph_u32 v, w;

		v = ((sph_u32)i << 24)
			| ((sph_u32)(i + 1) << 16)
			| ((sph_u32)(i + 2) << 8)
			| (sph_u32)(i + 3);
		w = ((sph_u32)(i + 3) << 24)
			| ((sph_u32)(i + 2) << 16)
			| ((sph_u32)(i + 1) << 8)
			| (sph_u32)i;
		if (i % 4 == 0) {
			sph_enc32be_aligned(u.bytes + i, v);
		} else {
			sph_enc32be(u.bytes + i, v);
		}
		ASSERT(u.bytes[i + 0] == i + 0);
		ASSERT(u.bytes[i + 1] == i + 1);
		ASSERT(u.bytes[i + 2] == i + 2);
		ASSERT(u.bytes[i + 3] == i + 3);
		memset(u.bytes, 0, sizeof u.bytes);
		if (i % 4 == 0) {
			sph_enc32le_aligned(u.bytes + i, w);
		} else {
			sph_enc32le(u.bytes + i, w);
		}
		ASSERT(u.bytes[i + 0] == i + 0);
		ASSERT(u.bytes[i + 1] == i + 1);
		ASSERT(u.bytes[i + 2] == i + 2);
		ASSERT(u.bytes[i + 3] == i + 3);
	}
}

#ifdef SPH_64
static void
test_types64(void)
{
	unsigned i;
	union {
		unsigned char bytes[64];
		sph_u64 v64;
	} u;

#if defined SPH_LITTLE_ENDIAN || defined SPH_BIG_ENDIAN
	ASSERT(sizeof(sph_u64) == 8);
#else
	ASSERT(sizeof(sph_u64) >= 8);
#endif

	for (i = 0; i < sizeof u.bytes; i ++)
		u.bytes[i] = i;
	for (i = 0; (i + 7) < sizeof u.bytes; i ++) {
		sph_u64 v, w;

		v = ((sph_u64)i << 56)
			| ((sph_u64)(i + 1) << 48)
			| ((sph_u64)(i + 2) << 40)
			| ((sph_u64)(i + 3) << 32)
			| ((sph_u64)(i + 4) << 24)
			| ((sph_u64)(i + 5) << 16)
			| ((sph_u64)(i + 6) << 8)
			| (sph_u64)(i + 7);
		w = ((sph_u64)(i + 7) << 56)
			| ((sph_u64)(i + 6) << 48)
			| ((sph_u64)(i + 5) << 40)
			| ((sph_u64)(i + 4) << 32)
			| ((sph_u64)(i + 3) << 24)
			| ((sph_u64)(i + 2) << 16)
			| ((sph_u64)(i + 1) << 8)
			| (sph_u64)i;
		ASSERT(sph_dec64be(u.bytes + i) == v);
		ASSERT(sph_dec64le(u.bytes + i) == w);
		if (i % 8 == 0) {
			ASSERT(sph_dec64be_aligned(u.bytes + i) == v);
			ASSERT(sph_dec64le_aligned(u.bytes + i) == w);
		}
	}
	memset(u.bytes, 0, sizeof u.bytes);
	for (i = 0; (i + 7) < sizeof u.bytes; i ++) {
		sph_u64 v, w;

		v = ((sph_u64)i << 56)
			| ((sph_u64)(i + 1) << 48)
			| ((sph_u64)(i + 2) << 40)
			| ((sph_u64)(i + 3) << 32)
			| ((sph_u64)(i + 4) << 24)
			| ((sph_u64)(i + 5) << 16)
			| ((sph_u64)(i + 6) << 8)
			| (sph_u64)(i + 7);
		w = ((sph_u64)(i + 7) << 56)
			| ((sph_u64)(i + 6) << 48)
			| ((sph_u64)(i + 5) << 40)
			| ((sph_u64)(i + 4) << 32)
			| ((sph_u64)(i + 3) << 24)
			| ((sph_u64)(i + 2) << 16)
			| ((sph_u64)(i + 1) << 8)
			| (sph_u64)i;
		if (i % 8 == 0) {
			sph_enc64be_aligned(u.bytes + i, v);
		} else {
			sph_enc64be(u.bytes + i, v);
		}
		ASSERT(u.bytes[i + 0] == i + 0);
		ASSERT(u.bytes[i + 1] == i + 1);
		ASSERT(u.bytes[i + 2] == i + 2);
		ASSERT(u.bytes[i + 3] == i + 3);
		ASSERT(u.bytes[i + 4] == i + 4);
		ASSERT(u.bytes[i + 5] == i + 5);
		ASSERT(u.bytes[i + 6] == i + 6);
		ASSERT(u.bytes[i + 7] == i + 7);
		memset(u.bytes, 0, sizeof u.bytes);
		if (i % 8 == 0) {
			sph_enc64le_aligned(u.bytes + i, w);
		} else {
			sph_enc64le(u.bytes + i, w);
		}
		ASSERT(u.bytes[i + 0] == i + 0);
		ASSERT(u.bytes[i + 1] == i + 1);
		ASSERT(u.bytes[i + 2] == i + 2);
		ASSERT(u.bytes[i + 3] == i + 3);
		ASSERT(u.bytes[i + 4] == i + 4);
		ASSERT(u.bytes[i + 5] == i + 5);
		ASSERT(u.bytes[i + 6] == i + 6);
		ASSERT(u.bytes[i + 7] == i + 7);
	}
}
#endif

static void
test_types(void)
{
	test_config();
	test_types32();
#ifdef SPH_64
	test_types64();
#else
	printf("warning: no 64-bit type defined\n");
#endif
}

UTEST_MAIN("types", test_types)
