// $Id: JH224.java 156 2010-04-26 17:55:11Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the JH-224 digest algorithm under the
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

public class JH224 extends JHCore {

	private static final long[] IV = {
		0x82c270e00bed0230L, 0x8d0c3a9e31ce34b1L,
		0x8f0c942fba46cd87L, 0x1ec4d80afc7971c4L,
		0x61e01abb69962d7bL, 0xaf71893de13d8697L,
		0xd2520460f7c9c094L, 0xc76349ca3da5799cL,
		0xfd8b551fbdbceb9fL, 0x0834bd5bb442f8bfL,
		0xba515c35b9c7999eL, 0x55a44e6271cc13b3L,
		0x85725793c185f725L, 0x45366b69005025d2L,
		0x3390ebdb27dd1edfL, 0xccbaade17e603de9L
	};

	/**
	 * Create the engine.
	 */
	public JH224()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new JH224());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 28;
	}

	/** @see JHCore */
	long[] getIV()
	{
		return IV;
	}
}
