/* $Id: test_shabal.c 154 2010-04-26 17:00:24Z tp $ */
/*
 * Unit tests for the SHABAL hash functions.
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

#include "sph_shabal.h"
#include "test_digest_helper.c"

TEST_DIGEST_INTERNAL(SHABAL-192, shabal192, 24)
TEST_DIGEST_INTERNAL(SHABAL-224, shabal224, 28)
TEST_DIGEST_INTERNAL(SHABAL-256, shabal256, 32)
TEST_DIGEST_INTERNAL(SHABAL-384, shabal384, 48)
TEST_DIGEST_INTERNAL(SHABAL-512, shabal512, 64)

static void
test_shabal(void)
{
	test_shabal192_internal(
		"abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLM"
		"NOPQRSTUVWXYZ-0123456789-abcdefghijklmnopqrstuvwxyz",
		"690fae79226d95760ae8fdb4f58c0537111756557d307b15");

	test_shabal224_internal(
		"abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLM"
		"NOPQRSTUVWXYZ-0123456789-abcdefghijklmnopqrstuvwxyz",
		"c7d62d8d2a3474b4f4a9d11a52db3d435bf158cf454c5d561d7125f5");

	test_shabal256_internal(
		"abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLM"
		"NOPQRSTUVWXYZ-0123456789-abcdefghijklmnopqrstuvwxyz",
		"b49f34bf51864c30533cc46cc2542bdec2f96fd06f5c539aff6ead58"
		"83f7327a");

	test_shabal384_internal(
		"abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLM"
		"NOPQRSTUVWXYZ-0123456789-abcdefghijklmnopqrstuvwxyz",
		"30012c0e3edc460bd78627c2c30944d2a189669afa2d7a97"
		"13ef2f774c4474a43af1cbcec5fab4248c0873f038fbeba0");

	test_shabal512_internal(
		"abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLM"
		"NOPQRSTUVWXYZ-0123456789-abcdefghijklmnopqrstuvwxyz",
		"677e6f7f12d70af0b335662f59b56851f3653e66647d3386"
		"dfda0143254cc8a5db3e2194068c6f71597d7b60984d22b4"
		"7a1f60d91ca8dfcb175d65b97359cecf");
}

UTEST_MAIN("SHABAL", test_shabal)
