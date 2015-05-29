// $Id: SHABAL512.java 176 2010-05-07 16:05:14Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the Shabal-512 digest algorithm under the
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

public class SHABAL512 extends SHABALCore {

	private static final int[] A_init_512 = {
		0x20728DFD, 0x46C0BD53, 0xE782B699, 0x55304632,
		0x71B4EF90, 0x0EA9E82C, 0xDBB930F1, 0xFAD06B8B,
		0xBE0CAE40, 0x8BD14410, 0x76D2ADAC, 0x28ACAB7F
	};

	private static final int[] B_init_512 = {
		0xC1099CB7, 0x07B385F3, 0xE7442C26, 0xCC8AD640,
		0xEB6F56C7, 0x1EA81AA9, 0x73B9D314, 0x1DE85D08,
		0x48910A5A, 0x893B22DB, 0xC5A0DF44, 0xBBC4324E,
		0x72D2F240, 0x75941D99, 0x6D8BDE82, 0xA1A7502B
	};

	private static final int[] C_init_512 = {
		0xD9BF68D1, 0x58BAD750, 0x56028CB2, 0x8134F359,
		0xB5D469D8, 0x941A8CC2, 0x418B2A6E, 0x04052780,
		0x7F07D787, 0x5194358F, 0x3C60D665, 0xBE97D79A,
		0x950C3434, 0xAED9A06D, 0x2537DC8D, 0x7CDB5969
	};

	/**
	 * Create the engine.
	 */
	public SHABAL512()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new SHABAL512());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 64;
	}

	/** @see SHABALCore */
	int[] getInitA()
	{
		return A_init_512;
	}

	/** @see SHABALCore */
	int[] getInitB()
	{
		return B_init_512;
	}

	/** @see SHABALCore */
	int[] getInitC()
	{
		return C_init_512;
	}
}
