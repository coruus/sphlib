// $Id: JH384.java 156 2010-04-26 17:55:11Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the JH-384 digest algorithm under the
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
 * @version   $Revision: 156 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class JH384 extends JHCore {

	private static final long[] IV = {
		0x079c23ab64ab2d40L, 0x8cb51ce447dee98dL,
		0x8d9bb1627ec25269L, 0xbab62d2b002ffc80L,
		0xcbafbcef308c173aL, 0xad6fa3aa31194031L,
		0x898977423a6f4ce3L, 0xbf2e732b440ddb7dL,
		0xf2c43ecaa63a54e5L, 0x8a37b80afc4422c5L,
		0xa397c3bc04e9e091L, 0x37a80453e14860faL,
		0x7131d33a5fd4bea6L, 0xdcda4af8f4338512L,
		0x6ec7f8f4c84958d0L, 0x8b9e94a34695b6a9L
	};

	/**
	 * Create the engine.
	 */
	public JH384()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new JH384());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 48;
	}

	/** @see JHCore */
	long[] getIV()
	{
		return IV;
	}
}
