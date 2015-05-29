// $Id: Speed.java 166 2010-05-03 16:44:36Z tp $

package fr.cryptohash.test;

import fr.cryptohash.Digest;
import fr.cryptohash.MD2;
import fr.cryptohash.MD4;
import fr.cryptohash.MD5;
import fr.cryptohash.SHA0;
import fr.cryptohash.SHA1;
import fr.cryptohash.SHA224;
import fr.cryptohash.SHA256;
import fr.cryptohash.SHA384;
import fr.cryptohash.SHA512;
import fr.cryptohash.RIPEMD;
import fr.cryptohash.RIPEMD128;
import fr.cryptohash.RIPEMD160;
import fr.cryptohash.Tiger;
import fr.cryptohash.Tiger2;
import fr.cryptohash.PANAMA;
import fr.cryptohash.HAVAL256_3;
import fr.cryptohash.HAVAL256_4;
import fr.cryptohash.HAVAL256_5;
import fr.cryptohash.SHABAL192;
import fr.cryptohash.SHABAL224;
import fr.cryptohash.SHABAL256;
import fr.cryptohash.SHABAL384;
import fr.cryptohash.SHABAL512;
import fr.cryptohash.BLAKE224;
import fr.cryptohash.BLAKE256;
import fr.cryptohash.BLAKE384;
import fr.cryptohash.BLAKE512;
import fr.cryptohash.Luffa224;
import fr.cryptohash.Luffa256;
import fr.cryptohash.Luffa384;
import fr.cryptohash.Luffa512;
import fr.cryptohash.ECHO224;
import fr.cryptohash.ECHO256;
import fr.cryptohash.ECHO384;
import fr.cryptohash.ECHO512;
import fr.cryptohash.SIMD224;
import fr.cryptohash.SIMD256;
import fr.cryptohash.SIMD384;
import fr.cryptohash.SIMD512;
import fr.cryptohash.Skein224;
import fr.cryptohash.Skein256;
import fr.cryptohash.Skein384;
import fr.cryptohash.Skein512;
import fr.cryptohash.JH224;
import fr.cryptohash.JH256;
import fr.cryptohash.JH384;
import fr.cryptohash.JH512;
import fr.cryptohash.Fugue224;
import fr.cryptohash.Fugue256;
import fr.cryptohash.Fugue384;
import fr.cryptohash.Fugue512;
import fr.cryptohash.BMW224;
import fr.cryptohash.BMW256;
import fr.cryptohash.BMW384;
import fr.cryptohash.BMW512;
import fr.cryptohash.WHIRLPOOL;

/**
 * <p>This class implements some speed tests for hash functions.</p>
 *
 * <pre>
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
 * </pre>
 *
 * @version   $Revision: 166 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class Speed {

	/**
	 * Program entry point. The arguments should be function names,
	 * for which speed is measured. If no argument is given, then
	 * all implemented functions are benchmarked.
	 *
	 * @param args   the program arguments
	 */
	public static void main(String[] args)
	{
		long todo = 0;
		for (int i = 0; i < args.length; i ++) {
			String s = normalize(args[i]);
			if (s.equals("md2"))
				todo |= DO_MD2;
			else if (s.equals("md4"))
				todo |= DO_MD4;
			else if (s.equals("md5"))
				todo |= DO_MD5;
			else if (s.equals("sha0"))
				todo |= DO_SHA0;
			else if (s.equals("sha1"))
				todo |= DO_SHA1;
			else if (s.equals("sha2"))
				todo |= DO_SHA256 | DO_SHA512;
			else if (s.equals("sha224"))
				todo |= DO_SHA224;
			else if (s.equals("sha256"))
				todo |= DO_SHA256;
			else if (s.equals("sha384"))
				todo |= DO_SHA384;
			else if (s.equals("sha512"))
				todo |= DO_SHA512;
			else if (s.equals("rmd") || s.equals("ripemd"))
				todo |= DO_RIPEMD;
			else if (s.equals("rmd128") || s.equals("ripemd128"))
				todo |= DO_RIPEMD128;
			else if (s.equals("rmd160") || s.equals("ripemd160"))
				todo |= DO_RIPEMD160;
			else if (s.equals("tiger"))
				todo |= DO_TIGER;
			else if (s.equals("tiger2"))
				todo |= DO_TIGER2;
			else if (s.equals("panama"))
				todo |= DO_PANAMA;
			else if (s.equals("haval3"))
				todo |= DO_HAVAL3;
			else if (s.equals("haval4"))
				todo |= DO_HAVAL4;
			else if (s.equals("haval5"))
				todo |= DO_HAVAL5;
			else if (s.equals("whirlpool"))
				todo |= DO_WHIRLPOOL;
			else if (s.equals("shabal"))
				todo |= DO_SHABAL512;
			else if (s.equals("shabal192"))
				todo |= DO_SHABAL192;
			else if (s.equals("shabal224"))
				todo |= DO_SHABAL224;
			else if (s.equals("shabal256"))
				todo |= DO_SHABAL256;
			else if (s.equals("shabal384"))
				todo |= DO_SHABAL384;
			else if (s.equals("shabal512"))
				todo |= DO_SHABAL512;
			else if (s.equals("blake"))
				todo |= DO_BLAKE256 | DO_BLAKE512;
			else if (s.equals("blake224"))
				todo |= DO_BLAKE224;
			else if (s.equals("blake256"))
				todo |= DO_BLAKE256;
			else if (s.equals("blake384"))
				todo |= DO_BLAKE384;
			else if (s.equals("blake512"))
				todo |= DO_BLAKE512;
			else if (s.equals("luffa"))
				todo |= DO_LUFFA256 | DO_LUFFA384 | DO_LUFFA512;
			else if (s.equals("luffa224"))
				todo |= DO_LUFFA224;
			else if (s.equals("luffa256"))
				todo |= DO_LUFFA256;
			else if (s.equals("luffa384"))
				todo |= DO_LUFFA384;
			else if (s.equals("luffa512"))
				todo |= DO_LUFFA512;
			else if (s.equals("echo"))
				todo |= DO_ECHO256 | DO_ECHO512;
			else if (s.equals("echo224"))
				todo |= DO_ECHO224;
			else if (s.equals("echo256"))
				todo |= DO_ECHO256;
			else if (s.equals("echo384"))
				todo |= DO_ECHO384;
			else if (s.equals("echo512"))
				todo |= DO_ECHO512;
			else if (s.equals("simd"))
				todo |= DO_SIMD256 | DO_SIMD512;
			else if (s.equals("simd224"))
				todo |= DO_SIMD224;
			else if (s.equals("simd256"))
				todo |= DO_SIMD256;
			else if (s.equals("simd384"))
				todo |= DO_SIMD384;
			else if (s.equals("simd512"))
				todo |= DO_SIMD512;
			else if (s.equals("skein"))
				todo |= DO_SKEIN256 | DO_SKEIN512;
			else if (s.equals("skein224"))
				todo |= DO_SKEIN224;
			else if (s.equals("skein256"))
				todo |= DO_SKEIN256;
			else if (s.equals("skein384"))
				todo |= DO_SKEIN384;
			else if (s.equals("skein512"))
				todo |= DO_SKEIN512;
			else if (s.equals("jh"))
				todo |= DO_JH512;
			else if (s.equals("jh224"))
				todo |= DO_JH224;
			else if (s.equals("jh256"))
				todo |= DO_JH256;
			else if (s.equals("jh384"))
				todo |= DO_JH384;
			else if (s.equals("jh512"))
				todo |= DO_JH512;
			else if (s.equals("fugue"))
				todo |= DO_FUGUE256 | DO_FUGUE384 | DO_FUGUE512;
			else if (s.equals("fugue224"))
				todo |= DO_FUGUE224;
			else if (s.equals("fugue256"))
				todo |= DO_FUGUE256;
			else if (s.equals("fugue384"))
				todo |= DO_FUGUE384;
			else if (s.equals("fugue512"))
				todo |= DO_FUGUE512;
			else if (s.equals("bmw"))
				todo |= DO_BMW256 | DO_BMW512;
			else if (s.equals("bmw224"))
				todo |= DO_BMW224;
			else if (s.equals("bmw256"))
				todo |= DO_BMW256;
			else if (s.equals("bmw384"))
				todo |= DO_BMW384;
			else if (s.equals("bmw512"))
				todo |= DO_BMW512;
			else
				usage(args[i]);
		}
		if (todo == 0L)
			todo = -1L;
		if ((todo & DO_MD2) != 0)
			speed("MD2", new MD2());
		if ((todo & DO_MD4) != 0)
			speed("MD4", new MD4());
		if ((todo & DO_MD5) != 0)
			speed("MD5", new MD5());
		if ((todo & DO_SHA0) != 0)
			speed("SHA-0", new SHA0());
		if ((todo & DO_SHA1) != 0)
			speed("SHA-1", new SHA1());
		if ((todo & DO_SHA224) != 0)
			speed("SHA-224", new SHA224());
		if ((todo & DO_SHA256) != 0)
			speed("SHA-256", new SHA256());
		if ((todo & DO_SHA384) != 0)
			speed("SHA-384", new SHA384());
		if ((todo & DO_SHA512) != 0)
			speed("SHA-512", new SHA512());
		if ((todo & DO_RIPEMD) != 0)
			speed("RIPEMD", new RIPEMD());
		if ((todo & DO_RIPEMD128) != 0)
			speed("RIPEMD-128", new RIPEMD128());
		if ((todo & DO_RIPEMD160) != 0)
			speed("RIPEMD-160", new RIPEMD160());
		if ((todo & DO_TIGER) != 0)
			speed("Tiger", new Tiger());
		if ((todo & DO_TIGER2) != 0)
			speed("Tiger2", new Tiger2());
		if ((todo & DO_PANAMA) != 0)
			speed("PANAMA", new PANAMA());
		if ((todo & DO_HAVAL3) != 0)
			speed("HAVAL[3 passes]", new HAVAL256_3());
		if ((todo & DO_HAVAL4) != 0)
			speed("HAVAL[4 passes]", new HAVAL256_4());
		if ((todo & DO_HAVAL5) != 0)
			speed("HAVAL[5 passes]", new HAVAL256_5());
		if ((todo & DO_WHIRLPOOL) != 0)
			speed("WHIRLPOOL", new WHIRLPOOL());
		if ((todo & DO_SHABAL192) != 0)
			speed("SHABAL-192", new SHABAL192());
		if ((todo & DO_SHABAL224) != 0)
			speed("SHABAL-224", new SHABAL224());
		if ((todo & DO_SHABAL256) != 0)
			speed("SHABAL-256", new SHABAL256());
		if ((todo & DO_SHABAL384) != 0)
			speed("SHABAL-384", new SHABAL384());
		if ((todo & DO_SHABAL512) != 0)
			speed("SHABAL-512", new SHABAL512());
		if ((todo & DO_BLAKE224) != 0)
			speed("BLAKE-224", new BLAKE224());
		if ((todo & DO_BLAKE256) != 0)
			speed("BLAKE-256", new BLAKE256());
		if ((todo & DO_BLAKE384) != 0)
			speed("BLAKE-384", new BLAKE384());
		if ((todo & DO_BLAKE512) != 0)
			speed("BLAKE-512", new BLAKE512());
		if ((todo & DO_LUFFA224) != 0)
			speed("Luffa-224", new Luffa224());
		if ((todo & DO_LUFFA256) != 0)
			speed("Luffa-256", new Luffa256());
		if ((todo & DO_LUFFA384) != 0)
			speed("Luffa-384", new Luffa384());
		if ((todo & DO_LUFFA512) != 0)
			speed("Luffa-512", new Luffa512());
		if ((todo & DO_ECHO224) != 0)
			speed("ECHO-224", new ECHO224());
		if ((todo & DO_ECHO256) != 0)
			speed("ECHO-256", new ECHO256());
		if ((todo & DO_ECHO384) != 0)
			speed("ECHO-384", new ECHO384());
		if ((todo & DO_ECHO512) != 0)
			speed("ECHO-512", new ECHO512());
		if ((todo & DO_SIMD224) != 0)
			speed("SIMD-224", new SIMD224());
		if ((todo & DO_SIMD256) != 0)
			speed("SIMD-256", new SIMD256());
		if ((todo & DO_SIMD384) != 0)
			speed("SIMD-384", new SIMD384());
		if ((todo & DO_SIMD512) != 0)
			speed("SIMD-512", new SIMD512());
		if ((todo & DO_SKEIN224) != 0)
			speed("Skein-224", new Skein224());
		if ((todo & DO_SKEIN256) != 0)
			speed("Skein-256", new Skein256());
		if ((todo & DO_SKEIN384) != 0)
			speed("Skein-384", new Skein384());
		if ((todo & DO_SKEIN512) != 0)
			speed("Skein-512", new Skein512());
		if ((todo & DO_JH224) != 0)
			speed("JH-224", new JH224());
		if ((todo & DO_JH256) != 0)
			speed("JH-256", new JH256());
		if ((todo & DO_JH384) != 0)
			speed("JH-384", new JH384());
		if ((todo & DO_JH512) != 0)
			speed("JH-512", new JH512());
		if ((todo & DO_FUGUE224) != 0)
			speed("Fugue-224", new Fugue224());
		if ((todo & DO_FUGUE256) != 0)
			speed("Fugue-256", new Fugue256());
		if ((todo & DO_FUGUE384) != 0)
			speed("Fugue-384", new Fugue384());
		if ((todo & DO_FUGUE512) != 0)
			speed("Fugue-512", new Fugue512());
		if ((todo & DO_BMW224) != 0)
			speed("BMW-224", new BMW224());
		if ((todo & DO_BMW256) != 0)
			speed("BMW-256", new BMW256());
		if ((todo & DO_BMW384) != 0)
			speed("BMW-384", new BMW384());
		if ((todo & DO_BMW512) != 0)
			speed("BMW-512", new BMW512());
	}

	private static final long DO_MD2        = 0x0000000000000001L;
	private static final long DO_MD4        = 0x0000000000000002L;
	private static final long DO_MD5        = 0x0000000000000004L;
	private static final long DO_SHA0       = 0x0000000000000008L;
	private static final long DO_SHA1       = 0x0000000000000010L;
	private static final long DO_SHA224     = 0x0000000000000020L;
	private static final long DO_SHA256     = 0x0000000000000040L;
	private static final long DO_SHA384     = 0x0000000000000080L;
	private static final long DO_SHA512     = 0x0000000000000100L;
	private static final long DO_RIPEMD     = 0x0000000000000200L;
	private static final long DO_RIPEMD128  = 0x0000000000000400L;
	private static final long DO_RIPEMD160  = 0x0000000000000800L;
	private static final long DO_TIGER      = 0x0000000000001000L;
	private static final long DO_TIGER2     = 0x0000000000002000L;
	private static final long DO_PANAMA     = 0x0000000000004000L;
	private static final long DO_HAVAL3     = 0x0000000000008000L;
	private static final long DO_HAVAL4     = 0x0000000000010000L;
	private static final long DO_HAVAL5     = 0x0000000000020000L;
	private static final long DO_WHIRLPOOL  = 0x0000000000040000L;
	private static final long DO_SHABAL192  = 0x0000000000080000L;
	private static final long DO_SHABAL224  = 0x0000000000100000L;
	private static final long DO_SHABAL256  = 0x0000000000200000L;
	private static final long DO_SHABAL384  = 0x0000000000400000L;
	private static final long DO_SHABAL512  = 0x0000000000800000L;
	private static final long DO_BLAKE224   = 0x0000000001000000L;
	private static final long DO_BLAKE256   = 0x0000000002000000L;
	private static final long DO_BLAKE384   = 0x0000000004000000L;
	private static final long DO_BLAKE512   = 0x0000000008000000L;
	private static final long DO_LUFFA224   = 0x0000000010000000L;
	private static final long DO_LUFFA256   = 0x0000000020000000L;
	private static final long DO_LUFFA384   = 0x0000000040000000L;
	private static final long DO_LUFFA512   = 0x0000000080000000L;
	private static final long DO_ECHO224    = 0x0000000100000000L;
	private static final long DO_ECHO256    = 0x0000000200000000L;
	private static final long DO_ECHO384    = 0x0000000400000000L;
	private static final long DO_ECHO512    = 0x0000000800000000L;
	private static final long DO_SIMD224    = 0x0000001000000000L;
	private static final long DO_SIMD256    = 0x0000002000000000L;
	private static final long DO_SIMD384    = 0x0000004000000000L;
	private static final long DO_SIMD512    = 0x0000008000000000L;
	private static final long DO_SKEIN224   = 0x0000010000000000L;
	private static final long DO_SKEIN256   = 0x0000020000000000L;
	private static final long DO_SKEIN384   = 0x0000040000000000L;
	private static final long DO_SKEIN512   = 0x0000080000000000L;
	private static final long DO_JH224      = 0x0000100000000000L;
	private static final long DO_JH256      = 0x0000200000000000L;
	private static final long DO_JH384      = 0x0000400000000000L;
	private static final long DO_JH512      = 0x0000800000000000L;
	private static final long DO_FUGUE224   = 0x0001000000000000L;
	private static final long DO_FUGUE256   = 0x0002000000000000L;
	private static final long DO_FUGUE384   = 0x0004000000000000L;
	private static final long DO_FUGUE512   = 0x0008000000000000L;
	private static final long DO_BMW224     = 0x0010000000000000L;
	private static final long DO_BMW256     = 0x0020000000000000L;
	private static final long DO_BMW384     = 0x0040000000000000L;
	private static final long DO_BMW512     = 0x0080000000000000L;

	private static String normalize(String name)
	{
		name = name.toLowerCase();
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < name.length(); i ++) {
			char c = name.charAt(i);
			if (c != '-' && c != '/')
				sb.append(c);
		}
		return sb.toString();
	}

	private static void usage(String name)
	{
		System.err.println("unknown hash function name: '"
			+ name + "'");
		System.exit(1);
	}

	private static void speed(String name, Digest dig)
	{
		System.out.println("Speed test: " + name);
		byte[] buf = new byte[8192];
		for (int i = 0; i < buf.length; i ++)
			buf[i] = 'a';
		long num = 2L;
		for (int clen = 16;; clen <<= 2) {
			if (clen == 4096) {
				clen = 8192;
				if (num > 1L)
					num >>= 1;
			}
			long tt;
			for (;;) {
				tt = speedUnit(dig, buf, clen, num);
				if (tt > 6000L) {
					if (num <= 1L)
						break;
					num >>= 1L;
				} else if (tt < 2000L) {
					num += num;
				} else {
					break;
				}
			}
			long tlen = (long)clen * num;
			long div = 10L * tt;
			long rate = (tlen + (div - 1) / 2) / div;
			System.out.println("message length = "
				+ formatLong((long)clen, 5)
				+ " -> "
				+ prependSpaces(Long.toString(rate / 100L), 4)
				+ "."
				+ prependZeroes(Long.toString(rate % 100L), 2)
				+ " MBytes/s");
			if (clen == 8192) {
				tt = speedLong(dig, buf, clen, num);
				tlen = (long)clen * num;
				div = 10L * tt;
				rate = (tlen + (div - 1) / 2) / div;
				System.out.println("long messages          -> "
					+ prependSpaces(
						Long.toString(rate / 100L), 4)
					+ "."
					+ prependZeroes(
						Long.toString(rate % 100L), 2)
					+ " MBytes/s");
				break;
			}
			if (num > 4L)
				num >>= 2;
		}
	}

	private static long speedUnit(Digest dig, byte[] buf, int len, long num)
	{
		byte[] out = new byte[dig.getDigestLength()];
		long orig = System.currentTimeMillis();
		while (num -- > 0) {
			dig.update(buf, 0, len);
			dig.digest(out, 0, out.length);
		}
		long end = System.currentTimeMillis();
		return end - orig;
	}

	private static long speedLong(Digest dig, byte[] buf, int len, long num)
	{
		byte[] out = new byte[dig.getDigestLength()];
		long orig = System.currentTimeMillis();
		while (num -- > 0) {
			dig.update(buf, 0, len);
		}
		long end = System.currentTimeMillis();
		dig.digest(out, 0, out.length);
		return end - orig;
	}

	private static String formatLong(long num, int len)
	{
		return prependSpaces(Long.toString(num), len);
	}

	private static String prependSpaces(String s, int len)
	{
		return prependChar(s, ' ', len);
	}

	private static String prependZeroes(String s, int len)
	{
		return prependChar(s, '0', len);
	}

	private static String prependChar(String s, char c, int len)
	{
		int slen = s.length();
		if (slen >= len)
			return s;
		StringBuffer sb = new StringBuffer();
		while (len -- > slen)
			sb.append(c);
		sb.append(s);
		return sb.toString();
	}
}
