// $Id: SHABAL224.java 176 2010-05-07 16:05:14Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the Shabal-224 digest algorithm under the
 * {@link Digest} API.</p>
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
 * @version   $Revision: 176 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class SHABAL224 extends SHABALCore {

	private static final int[] A_init_224 = {
		0xA5201467, 0xA9B8D94A, 0xD4CED997, 0x68379D7B,
		0xA7FC73BA, 0xF1A2546B, 0x606782BF, 0xE0BCFD0F,
		0x2F25374E, 0x069A149F, 0x5E2DFF25, 0xFAECF061
	};

	private static final int[] B_init_224 = {
		0xEC9905D8, 0xF21850CF, 0xC0A746C8, 0x21DAD498,
		0x35156EEB, 0x088C97F2, 0x26303E40, 0x8A2D4FB5,
		0xFEEE44B6, 0x8A1E9573, 0x7B81111A, 0xCBC139F0,
		0xA3513861, 0x1D2C362E, 0x918C580E, 0xB58E1B9C
	};

	private static final int[] C_init_224 = {
		0xE4B573A1, 0x4C1A0880, 0x1E907C51, 0x04807EFD,
		0x3AD8CDE5, 0x16B21302, 0x02512C53, 0x2204CB18,
		0x99405F2D, 0xE5B648A1, 0x70AB1D43, 0xA10C25C2,
		0x16F1AC05, 0x38BBEB56, 0x9B01DC60, 0xB1096D83
	};

	/**
	 * Create the engine.
	 */
	public SHABAL224()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new SHABAL224());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 28;
	}

	/** @see SHABALCore */
	int[] getInitA()
	{
		return A_init_224;
	}

	/** @see SHABALCore */
	int[] getInitB()
	{
		return B_init_224;
	}

	/** @see SHABALCore */
	int[] getInitC()
	{
		return C_init_224;
	}
}
