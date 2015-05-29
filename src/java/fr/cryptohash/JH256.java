// $Id: JH256.java 156 2010-04-26 17:55:11Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the JH-256 digest algorithm under the
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

public class JH256 extends JHCore {

	private static final long[] IV = {
		0xc968b8e2c53a596eL, 0x427e45ef1d7ae6e5L,
		0x6145b7d906711f7aL, 0x2fc7617806a92201L,
		0x7b2991c1b91929e2L, 0xc42b4ce18cc5a2d6L,
		0x6220beca901b5ddfL, 0xd3b205638ea7ac5fL,
		0x143e8cba6d313104L, 0xb0e7005490527271L,
		0x4cce321e075de510L, 0x1ba800ece2025178L,
		0x9f5772795fd104a5L, 0xf0b8b63425f5b238L,
		0x1670fa3e5f907f17L, 0xe28fc064e769ac90L
	};

	/**
	 * Create the engine.
	 */
	public JH256()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new JH256());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 32;
	}

	/** @see JHCore */
	long[] getIV()
	{
		return IV;
	}
}
