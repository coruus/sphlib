// $Id: SHABAL256.java 176 2010-05-07 16:05:14Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the Shabal-256 digest algorithm under the
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

public class SHABAL256 extends SHABALCore {

	private static final int[] A_init_256 = {
		0x52F84552, 0xE54B7999, 0x2D8EE3EC, 0xB9645191,
		0xE0078B86, 0xBB7C44C9, 0xD2B5C1CA, 0xB0D2EB8C,
		0x14CE5A45, 0x22AF50DC, 0xEFFDBC6B, 0xEB21B74A
	};

	private static final int[] B_init_256 = {
		0xB555C6EE, 0x3E710596, 0xA72A652F, 0x9301515F,
		0xDA28C1FA, 0x696FD868, 0x9CB6BF72, 0x0AFE4002,
		0xA6E03615, 0x5138C1D4, 0xBE216306, 0xB38B8890,
		0x3EA8B96B, 0x3299ACE4, 0x30924DD4, 0x55CB34A5
	};

	private static final int[] C_init_256 = {
		0xB405F031, 0xC4233EBA, 0xB3733979, 0xC0DD9D55,
		0xC51C28AE, 0xA327B8E1, 0x56C56167, 0xED614433,
		0x88B59D60, 0x60E2CEBA, 0x758B4B8B, 0x83E82A7F,
		0xBC968828, 0xE6E00BF7, 0xBA839E55, 0x9B491C60
	};

	/**
	 * Create the engine.
	 */
	public SHABAL256()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new SHABAL256());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 32;
	}

	/** @see SHABALCore */
	int[] getInitA()
	{
		return A_init_256;
	}

	/** @see SHABALCore */
	int[] getInitB()
	{
		return B_init_256;
	}

	/** @see SHABALCore */
	int[] getInitC()
	{
		return C_init_256;
	}
}
