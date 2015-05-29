// $Id: JH512.java 156 2010-04-26 17:55:11Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the JH-512 digest algorithm under the
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

public class JH512 extends JHCore {

	private static final long[] IV = {
		0x50ab6058c60942ccL, 0x4ce7a54cbdb9dc1bL,
		0xaf2e7afbd1a15e24L, 0xe5f44eabc4d5c0a1L,
		0x4cf243660c562073L, 0x999381ea9a8b3d18L,
		0xcf65d9fca940b6c7L, 0x9e831273befe3b66L,
		0x0f9a2f7e0a32d8e0L, 0x17d491558e0b1340L,
		0x05b5e4dec44e5f3fL, 0x8cbc5aee98fd1d32L,
		0x14081c25e46ce6c4L, 0x1b4b95bce1bd43dbL,
		0x7f229ec243b68014L, 0x0a33b909333c0303L
	};

	/**
	 * Create the engine.
	 */
	public JH512()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new JH512());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 64;
	}

	/** @see JHCore */
	long[] getIV()
	{
		return IV;
	}
}
