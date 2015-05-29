// $Id: SHABAL192.java 176 2010-05-07 16:05:14Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the Shabal-192 digest algorithm under the
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

public class SHABAL192 extends SHABALCore {

	private static final int[] A_init_192 = {
		0xFD749ED4, 0xB798E530, 0x33904B6F, 0x46BDA85E,
		0x076934B4, 0x454B4058, 0x77F74527, 0xFB4CF465,
		0x62931DA9, 0xE778C8DB, 0x22B3998E, 0xAC15CFB9
	};

	private static final int[] B_init_192 = {
		0x58BCBAC4, 0xEC47A08E, 0xAEE933B2, 0xDFCBC824,
		0xA7944804, 0xBF65BDB0, 0x5A9D4502, 0x59979AF7,
		0xC5CEA54E, 0x4B6B8150, 0x16E71909, 0x7D632319,
		0x930573A0, 0xF34C63D1, 0xCAF914B4, 0xFDD6612C
	};

	private static final int[] C_init_192 = {
		0x61550878, 0x89EF2B75, 0xA1660C46, 0x7EF3855B,
		0x7297B58C, 0x1BC67793, 0x7FB1C723, 0xB66FC640,
		0x1A48B71C, 0xF0976D17, 0x088CE80A, 0xA454EDF3,
		0x1C096BF4, 0xAC76224B, 0x5215781C, 0xCD5D2669
	};

	/**
	 * Create the engine.
	 */
	public SHABAL192()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new SHABAL192());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 24;
	}

	/** @see SHABALCore */
	int[] getInitA()
	{
		return A_init_192;
	}

	/** @see SHABALCore */
	int[] getInitB()
	{
		return B_init_192;
	}

	/** @see SHABALCore */
	int[] getInitC()
	{
		return C_init_192;
	}
}
