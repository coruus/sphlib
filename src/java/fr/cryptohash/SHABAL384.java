// $Id: SHABAL384.java 176 2010-05-07 16:05:14Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the Shabal-384 digest algorithm under the
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

public class SHABAL384 extends SHABALCore {

	private static final int[] A_init_384 = {
		0xC8FCA331, 0xE55C504E, 0x003EBF26, 0xBB6B8D83,
		0x7B0448C1, 0x41B82789, 0x0A7C9601, 0x8D659CFF,
		0xB6E2673E, 0xCA54C77B, 0x1460FD7E, 0x3FCB8F2D
	};

	private static final int[] B_init_384 = {
		0x527291FC, 0x2A16455F, 0x78E627E5, 0x944F169F,
		0x1CA6F016, 0xA854EA25, 0x8DB98ABE, 0xF2C62641,
		0x30117DCB, 0xCF5C4309, 0x93711A25, 0xF9F671B8,
		0xB01D2116, 0x333F4B89, 0xB285D165, 0x86829B36
	};

	private static final int[] C_init_384 = {
		0xF764B11A, 0x76172146, 0xCEF6934D, 0xC6D28399,
		0xFE095F61, 0x5E6018B4, 0x5048ECF5, 0x51353261,
		0x6E6E36DC, 0x63130DAD, 0xA9C69BD6, 0x1E90EA0C,
		0x7C35073B, 0x28D95E6D, 0xAA340E0D, 0xCB3DEE70
	};

	/**
	 * Create the engine.
	 */
	public SHABAL384()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new SHABAL384());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 48;
	}

	/** @see SHABALCore */
	int[] getInitA()
	{
		return A_init_384;
	}

	/** @see SHABALCore */
	int[] getInitB()
	{
		return B_init_384;
	}

	/** @see SHABALCore */
	int[] getInitC()
	{
		return C_init_384;
	}
}
