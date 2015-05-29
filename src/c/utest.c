/* $Id: utest.c 154 2010-04-26 17:00:24Z tp $ */
/*
 * Functions for unit tests.
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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "utest.h"

static char *current_name = NULL;

/* see utest.h */
void
utest_setname(char *name)
{
	current_name = name;
}

/* see utest.h */
void
fail(char *fmt, ...)
{
	va_list ap;

	if (current_name == NULL)
		fprintf(stderr, "TEST FAILED: ");
	else
		fprintf(stderr, "TEST FAILED [%s]: ", current_name);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);
}

static int
hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	switch (c) {
	case 'a': case 'A': return 10;
	case 'b': case 'B': return 11;
	case 'c': case 'C': return 12;
	case 'd': case 'D': return 13;
	case 'e': case 'E': return 14;
	case 'f': case 'F': return 15;
	}
	return -1;
}

/* see utest.h */
size_t
utest_strtobin(void *dst, char *src)
{
	unsigned char *buf;
	int z;
	unsigned acc;

	buf = dst;
	z = 0;
	acc = 0;
	while (*src != 0) {
		int v;

		v = hexval(*src ++);
		if (v < 0)
			continue;
		if (z)
			*buf ++ = acc | v;
		else
			acc = (unsigned)v << 4;
		z = !z;
	}
	if (z)
		fail("incomplete last byte");
	return (size_t)(buf - (unsigned char *)dst);
}

/* see utest.h */
int
utest_byteequal(void *d1, void *d2, size_t len)
{
	return memcmp(d1, d2, len) == 0;
}

/* see utest.h */
void
utest_printarray(void *src, size_t len)
{
	unsigned char *buf;

	buf = src;
	while (len -- > 0)
		printf("%02X", (unsigned)*buf ++);
}

/* see utest.h */
void
utest_success(void)
{
	if (current_name != NULL)
		printf("====== test %s passed\n", current_name);
	fflush(stdout);
}
