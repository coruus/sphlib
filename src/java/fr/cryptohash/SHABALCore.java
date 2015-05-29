// $Id: SHABALCore.java 176 2010-05-07 16:05:14Z tp $

package fr.cryptohash;

/**
 * This class implements the core operations for the Shabal digest
 * algorithm.
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

abstract class SHABALCore extends DigestEngine {

	SHABALCore()
	{
	}

	private int[] Ainit, Binit, Cinit;
	private int[] A, B, C;
	private long W;
	private byte[] outBuf;
	private int outOff;
	private byte[] outTmp;

	/**
	 * Encode the 32-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in little-endian
	 * convention (least significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	static private final void encodeLEInt(int val, byte[] buf, int off)
	{
		buf[off + 0] = (byte)val;
		buf[off + 1] = (byte)(val >>> 8);
		buf[off + 2] = (byte)(val >>> 16);
		buf[off + 3] = (byte)(val >>> 24);
	}

	/**
	 * Decode a 32-bit little-endian word from the array {@code buf}
	 * at offset {@code off}.
	 *
	 * @param buf   the source buffer
	 * @param off   the source offset
	 * @return  the decoded value
	 */
	static private final int decodeLEInt(byte[] buf, int off)
	{
		return (buf[off] & 0xFF)
			| ((buf[off + 1] & 0xFF) << 8)
			| ((buf[off + 2] & 0xFF) << 16)
			| ((buf[off + 3] & 0xFF) << 24);
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		doReset();
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		// DECL_STATE
		int A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, AA, AB;
		int B0, B1, B2, B3, B4, B5, B6, B7;
		int B8, B9, BA, BB, BC, BD, BE, BF;
		int C0, C1, C2, C3, C4, C5, C6, C7;
		int C8, C9, CA, CB, CC, CD, CE, CF;
		int M0, M1, M2, M3, M4, M5, M6, M7;
		int M8, M9, MA, MB, MC, MD, ME, MF;

		// READ_STATE
		A0 = A[0];
		A1 = A[1];
		A2 = A[2];
		A3 = A[3];
		A4 = A[4];
		A5 = A[5];
		A6 = A[6];
		A7 = A[7];
		A8 = A[8];
		A9 = A[9];
		AA = A[10];
		AB = A[11];

		B0 = B[0];
		B1 = B[1];
		B2 = B[2];
		B3 = B[3];
		B4 = B[4];
		B5 = B[5];
		B6 = B[6];
		B7 = B[7];
		B8 = B[8];
		B9 = B[9];
		BA = B[10];
		BB = B[11];
		BC = B[12];
		BD = B[13];
		BE = B[14];
		BF = B[15];

		C0 = C[0];
		C1 = C[1];
		C2 = C[2];
		C3 = C[3];
		C4 = C[4];
		C5 = C[5];
		C6 = C[6];
		C7 = C[7];
		C8 = C[8];
		C9 = C[9];
		CA = C[10];
		CB = C[11];
		CC = C[12];
		CD = C[13];
		CE = C[14];
		CF = C[15];

		// DECODE_BLOCK
		M0 = decodeLEInt(data, 0);
		M1 = decodeLEInt(data, 4);
		M2 = decodeLEInt(data, 8);
		M3 = decodeLEInt(data, 12);
		M4 = decodeLEInt(data, 16);
		M5 = decodeLEInt(data, 20);
		M6 = decodeLEInt(data, 24);
		M7 = decodeLEInt(data, 28);
		M8 = decodeLEInt(data, 32);
		M9 = decodeLEInt(data, 36);
		MA = decodeLEInt(data, 40);
		MB = decodeLEInt(data, 44);
		MC = decodeLEInt(data, 48);
		MD = decodeLEInt(data, 52);
		ME = decodeLEInt(data, 56);
		MF = decodeLEInt(data, 60);

		// INPUT_BLOCK_ADD
		B0 += M0;
		B1 += M1;
		B2 += M2;
		B3 += M3;
		B4 += M4;
		B5 += M5;
		B6 += M6;
		B7 += M7;
		B8 += M8;
		B9 += M9;
		BA += MA;
		BB += MB;
		BC += MC;
		BD += MD;
		BE += ME;
		BF += MF;

		for (int i = 0;; i ++) {
			// XOR_W
			A0 ^= (int)W;
			A1 ^= (int)(W >>> 32);

			// APPLY_P
			B0 = (B0 << 17) | (B0 >>> 15);
			B1 = (B1 << 17) | (B1 >>> 15);
			B2 = (B2 << 17) | (B2 >>> 15);
			B3 = (B3 << 17) | (B3 >>> 15);
			B4 = (B4 << 17) | (B4 >>> 15);
			B5 = (B5 << 17) | (B5 >>> 15);
			B6 = (B6 << 17) | (B6 >>> 15);
			B7 = (B7 << 17) | (B7 >>> 15);
			B8 = (B8 << 17) | (B8 >>> 15);
			B9 = (B9 << 17) | (B9 >>> 15);
			BA = (BA << 17) | (BA >>> 15);
			BB = (BB << 17) | (BB >>> 15);
			BC = (BC << 17) | (BC >>> 15);
			BD = (BD << 17) | (BD >>> 15);
			BE = (BE << 17) | (BE >>> 15);
			BF = (BF << 17) | (BF >>> 15);

			A0 = ((A0 ^ (((AB << 15) | (AB >>> 17)) * 5) ^ C8) * 3)
				^ BD ^ (B9 & ~B6) ^ M0;
			B0 = ~(((B0 << 1) | (B0 >>> 31)) ^ A0);
			A1 = ((A1 ^ (((A0 << 15) | (A0 >>> 17)) * 5) ^ C7) * 3)
				^ BE ^ (BA & ~B7) ^ M1;
			B1 = ~(((B1 << 1) | (B1 >>> 31)) ^ A1);
			A2 = ((A2 ^ (((A1 << 15) | (A1 >>> 17)) * 5) ^ C6) * 3)
				^ BF ^ (BB & ~B8) ^ M2;
			B2 = ~(((B2 << 1) | (B2 >>> 31)) ^ A2);
			A3 = ((A3 ^ (((A2 << 15) | (A2 >>> 17)) * 5) ^ C5) * 3)
				^ B0 ^ (BC & ~B9) ^ M3;
			B3 = ~(((B3 << 1) | (B3 >>> 31)) ^ A3);
			A4 = ((A4 ^ (((A3 << 15) | (A3 >>> 17)) * 5) ^ C4) * 3)
				^ B1 ^ (BD & ~BA) ^ M4;
			B4 = ~(((B4 << 1) | (B4 >>> 31)) ^ A4);
			A5 = ((A5 ^ (((A4 << 15) | (A4 >>> 17)) * 5) ^ C3) * 3)
				^ B2 ^ (BE & ~BB) ^ M5;
			B5 = ~(((B5 << 1) | (B5 >>> 31)) ^ A5);
			A6 = ((A6 ^ (((A5 << 15) | (A5 >>> 17)) * 5) ^ C2) * 3)
				^ B3 ^ (BF & ~BC) ^ M6;
			B6 = ~(((B6 << 1) | (B6 >>> 31)) ^ A6);
			A7 = ((A7 ^ (((A6 << 15) | (A6 >>> 17)) * 5) ^ C1) * 3)
				^ B4 ^ (B0 & ~BD) ^ M7;
			B7 = ~(((B7 << 1) | (B7 >>> 31)) ^ A7);
			A8 = ((A8 ^ (((A7 << 15) | (A7 >>> 17)) * 5) ^ C0) * 3)
				^ B5 ^ (B1 & ~BE) ^ M8;
			B8 = ~(((B8 << 1) | (B8 >>> 31)) ^ A8);
			A9 = ((A9 ^ (((A8 << 15) | (A8 >>> 17)) * 5) ^ CF) * 3)
				^ B6 ^ (B2 & ~BF) ^ M9;
			B9 = ~(((B9 << 1) | (B9 >>> 31)) ^ A9);
			AA = ((AA ^ (((A9 << 15) | (A9 >>> 17)) * 5) ^ CE) * 3)
				^ B7 ^ (B3 & ~B0) ^ MA;
			BA = ~(((BA << 1) | (BA >>> 31)) ^ AA);
			AB = ((AB ^ (((AA << 15) | (AA >>> 17)) * 5) ^ CD) * 3)
				^ B8 ^ (B4 & ~B1) ^ MB;
			BB = ~(((BB << 1) | (BB >>> 31)) ^ AB);
			A0 = ((A0 ^ (((AB << 15) | (AB >>> 17)) * 5) ^ CC) * 3)
				^ B9 ^ (B5 & ~B2) ^ MC;
			BC = ~(((BC << 1) | (BC >>> 31)) ^ A0);
			A1 = ((A1 ^ (((A0 << 15) | (A0 >>> 17)) * 5) ^ CB) * 3)
				^ BA ^ (B6 & ~B3) ^ MD;
			BD = ~(((BD << 1) | (BD >>> 31)) ^ A1);
			A2 = ((A2 ^ (((A1 << 15) | (A1 >>> 17)) * 5) ^ CA) * 3)
				^ BB ^ (B7 & ~B4) ^ ME;
			BE = ~(((BE << 1) | (BE >>> 31)) ^ A2);
			A3 = ((A3 ^ (((A2 << 15) | (A2 >>> 17)) * 5) ^ C9) * 3)
				^ BC ^ (B8 & ~B5) ^ MF;
			BF = ~(((BF << 1) | (BF >>> 31)) ^ A3);

			A4 = ((A4 ^ (((A3 << 15) | (A3 >>> 17)) * 5) ^ C8) * 3)
				^ BD ^ (B9 & ~B6) ^ M0;
			B0 = ~(((B0 << 1) | (B0 >>> 31)) ^ A4);
			A5 = ((A5 ^ (((A4 << 15) | (A4 >>> 17)) * 5) ^ C7) * 3)
				^ BE ^ (BA & ~B7) ^ M1;
			B1 = ~(((B1 << 1) | (B1 >>> 31)) ^ A5);
			A6 = ((A6 ^ (((A5 << 15) | (A5 >>> 17)) * 5) ^ C6) * 3)
				^ BF ^ (BB & ~B8) ^ M2;
			B2 = ~(((B2 << 1) | (B2 >>> 31)) ^ A6);
			A7 = ((A7 ^ (((A6 << 15) | (A6 >>> 17)) * 5) ^ C5) * 3)
				^ B0 ^ (BC & ~B9) ^ M3;
			B3 = ~(((B3 << 1) | (B3 >>> 31)) ^ A7);
			A8 = ((A8 ^ (((A7 << 15) | (A7 >>> 17)) * 5) ^ C4) * 3)
				^ B1 ^ (BD & ~BA) ^ M4;
			B4 = ~(((B4 << 1) | (B4 >>> 31)) ^ A8);
			A9 = ((A9 ^ (((A8 << 15) | (A8 >>> 17)) * 5) ^ C3) * 3)
				^ B2 ^ (BE & ~BB) ^ M5;
			B5 = ~(((B5 << 1) | (B5 >>> 31)) ^ A9);
			AA = ((AA ^ (((A9 << 15) | (A9 >>> 17)) * 5) ^ C2) * 3)
				^ B3 ^ (BF & ~BC) ^ M6;
			B6 = ~(((B6 << 1) | (B6 >>> 31)) ^ AA);
			AB = ((AB ^ (((AA << 15) | (AA >>> 17)) * 5) ^ C1) * 3)
				^ B4 ^ (B0 & ~BD) ^ M7;
			B7 = ~(((B7 << 1) | (B7 >>> 31)) ^ AB);
			A0 = ((A0 ^ (((AB << 15) | (AB >>> 17)) * 5) ^ C0) * 3)
				^ B5 ^ (B1 & ~BE) ^ M8;
			B8 = ~(((B8 << 1) | (B8 >>> 31)) ^ A0);
			A1 = ((A1 ^ (((A0 << 15) | (A0 >>> 17)) * 5) ^ CF) * 3)
				^ B6 ^ (B2 & ~BF) ^ M9;
			B9 = ~(((B9 << 1) | (B9 >>> 31)) ^ A1);
			A2 = ((A2 ^ (((A1 << 15) | (A1 >>> 17)) * 5) ^ CE) * 3)
				^ B7 ^ (B3 & ~B0) ^ MA;
			BA = ~(((BA << 1) | (BA >>> 31)) ^ A2);
			A3 = ((A3 ^ (((A2 << 15) | (A2 >>> 17)) * 5) ^ CD) * 3)
				^ B8 ^ (B4 & ~B1) ^ MB;
			BB = ~(((BB << 1) | (BB >>> 31)) ^ A3);
			A4 = ((A4 ^ (((A3 << 15) | (A3 >>> 17)) * 5) ^ CC) * 3)
				^ B9 ^ (B5 & ~B2) ^ MC;
			BC = ~(((BC << 1) | (BC >>> 31)) ^ A4);
			A5 = ((A5 ^ (((A4 << 15) | (A4 >>> 17)) * 5) ^ CB) * 3)
				^ BA ^ (B6 & ~B3) ^ MD;
			BD = ~(((BD << 1) | (BD >>> 31)) ^ A5);
			A6 = ((A6 ^ (((A5 << 15) | (A5 >>> 17)) * 5) ^ CA) * 3)
				^ BB ^ (B7 & ~B4) ^ ME;
			BE = ~(((BE << 1) | (BE >>> 31)) ^ A6);
			A7 = ((A7 ^ (((A6 << 15) | (A6 >>> 17)) * 5) ^ C9) * 3)
				^ BC ^ (B8 & ~B5) ^ MF;
			BF = ~(((BF << 1) | (BF >>> 31)) ^ A7);

			A8 = ((A8 ^ (((A7 << 15) | (A7 >>> 17)) * 5) ^ C8) * 3)
				^ BD ^ (B9 & ~B6) ^ M0;
			B0 = ~(((B0 << 1) | (B0 >>> 31)) ^ A8);
			A9 = ((A9 ^ (((A8 << 15) | (A8 >>> 17)) * 5) ^ C7) * 3)
				^ BE ^ (BA & ~B7) ^ M1;
			B1 = ~(((B1 << 1) | (B1 >>> 31)) ^ A9);
			AA = ((AA ^ (((A9 << 15) | (A9 >>> 17)) * 5) ^ C6) * 3)
				^ BF ^ (BB & ~B8) ^ M2;
			B2 = ~(((B2 << 1) | (B2 >>> 31)) ^ AA);
			AB = ((AB ^ (((AA << 15) | (AA >>> 17)) * 5) ^ C5) * 3)
				^ B0 ^ (BC & ~B9) ^ M3;
			B3 = ~(((B3 << 1) | (B3 >>> 31)) ^ AB);
			A0 = ((A0 ^ (((AB << 15) | (AB >>> 17)) * 5) ^ C4) * 3)
				^ B1 ^ (BD & ~BA) ^ M4;
			B4 = ~(((B4 << 1) | (B4 >>> 31)) ^ A0);
			A1 = ((A1 ^ (((A0 << 15) | (A0 >>> 17)) * 5) ^ C3) * 3)
				^ B2 ^ (BE & ~BB) ^ M5;
			B5 = ~(((B5 << 1) | (B5 >>> 31)) ^ A1);
			A2 = ((A2 ^ (((A1 << 15) | (A1 >>> 17)) * 5) ^ C2) * 3)
				^ B3 ^ (BF & ~BC) ^ M6;
			B6 = ~(((B6 << 1) | (B6 >>> 31)) ^ A2);
			A3 = ((A3 ^ (((A2 << 15) | (A2 >>> 17)) * 5) ^ C1) * 3)
				^ B4 ^ (B0 & ~BD) ^ M7;
			B7 = ~(((B7 << 1) | (B7 >>> 31)) ^ A3);
			A4 = ((A4 ^ (((A3 << 15) | (A3 >>> 17)) * 5) ^ C0) * 3)
				^ B5 ^ (B1 & ~BE) ^ M8;
			B8 = ~(((B8 << 1) | (B8 >>> 31)) ^ A4);
			A5 = ((A5 ^ (((A4 << 15) | (A4 >>> 17)) * 5) ^ CF) * 3)
				^ B6 ^ (B2 & ~BF) ^ M9;
			B9 = ~(((B9 << 1) | (B9 >>> 31)) ^ A5);
			A6 = ((A6 ^ (((A5 << 15) | (A5 >>> 17)) * 5) ^ CE) * 3)
				^ B7 ^ (B3 & ~B0) ^ MA;
			BA = ~(((BA << 1) | (BA >>> 31)) ^ A6);
			A7 = ((A7 ^ (((A6 << 15) | (A6 >>> 17)) * 5) ^ CD) * 3)
				^ B8 ^ (B4 & ~B1) ^ MB;
			BB = ~(((BB << 1) | (BB >>> 31)) ^ A7);
			A8 = ((A8 ^ (((A7 << 15) | (A7 >>> 17)) * 5) ^ CC) * 3)
				^ B9 ^ (B5 & ~B2) ^ MC;
			BC = ~(((BC << 1) | (BC >>> 31)) ^ A8);
			A9 = ((A9 ^ (((A8 << 15) | (A8 >>> 17)) * 5) ^ CB) * 3)
				^ BA ^ (B6 & ~B3) ^ MD;
			BD = ~(((BD << 1) | (BD >>> 31)) ^ A9);
			AA = ((AA ^ (((A9 << 15) | (A9 >>> 17)) * 5) ^ CA) * 3)
				^ BB ^ (B7 & ~B4) ^ ME;
			BE = ~(((BE << 1) | (BE >>> 31)) ^ AA);
			AB = ((AB ^ (((AA << 15) | (AA >>> 17)) * 5) ^ C9) * 3)
				^ BC ^ (B8 & ~B5) ^ MF;
			BF = ~(((BF << 1) | (BF >>> 31)) ^ AB);

			AB += C6;
			AA += C5;
			A9 += C4;
			A8 += C3;
			A7 += C2;
			A6 += C1;
			A5 += C0;
			A4 += CF;
			A3 += CE;
			A2 += CD;
			A1 += CC;
			A0 += CB;
			AB += CA;
			AA += C9;
			A9 += C8;
			A8 += C7;
			A7 += C6;
			A6 += C5;
			A5 += C4;
			A4 += C3;
			A3 += C2;
			A2 += C1;
			A1 += C0;
			A0 += CF;
			AB += CE;
			AA += CD;
			A9 += CC;
			A8 += CB;
			A7 += CA;
			A6 += C9;
			A5 += C8;
			A4 += C7;
			A3 += C6;
			A2 += C5;
			A1 += C4;
			A0 += C3;

			if (outBuf == null)
				break;

			/*
			 * If we get there, then we are doing the final
			 * "blank" rounds.
			 */
			if (i == 3) {
				encodeLEInt(B0, outTmp, 0);
				encodeLEInt(B1, outTmp, 4);
				encodeLEInt(B2, outTmp, 8);
				encodeLEInt(B3, outTmp, 12);
				encodeLEInt(B4, outTmp, 16);
				encodeLEInt(B5, outTmp, 20);
				encodeLEInt(B6, outTmp, 24);
				encodeLEInt(B7, outTmp, 28);
				encodeLEInt(B8, outTmp, 32);
				encodeLEInt(B9, outTmp, 36);
				encodeLEInt(BA, outTmp, 40);
				encodeLEInt(BB, outTmp, 44);
				encodeLEInt(BC, outTmp, 48);
				encodeLEInt(BD, outTmp, 52);
				encodeLEInt(BE, outTmp, 56);
				encodeLEInt(BF, outTmp, 60);
				int dlen = getDigestLength();
				System.arraycopy(outTmp, 64 - dlen,
					outBuf, outOff, dlen);
				return;
			}

			// SWAP_BC
			int tmp;
			tmp = B0; B0 = C0; C0 = tmp;
			tmp = B1; B1 = C1; C1 = tmp;
			tmp = B2; B2 = C2; C2 = tmp;
			tmp = B3; B3 = C3; C3 = tmp;
			tmp = B4; B4 = C4; C4 = tmp;
			tmp = B5; B5 = C5; C5 = tmp;
			tmp = B6; B6 = C6; C6 = tmp;
			tmp = B7; B7 = C7; C7 = tmp;
			tmp = B8; B8 = C8; C8 = tmp;
			tmp = B9; B9 = C9; C9 = tmp;
			tmp = BA; BA = CA; CA = tmp;
			tmp = BB; BB = CB; CB = tmp;
			tmp = BC; BC = CC; CC = tmp;
			tmp = BD; BD = CD; CD = tmp;
			tmp = BE; BE = CE; CE = tmp;
			tmp = BF; BF = CF; CF = tmp;
		}

		// INPUT_BLOCK_SUB
		C0 -= M0;
		C1 -= M1;
		C2 -= M2;
		C3 -= M3;
		C4 -= M4;
		C5 -= M5;
		C6 -= M6;
		C7 -= M7;
		C8 -= M8;
		C9 -= M9;
		CA -= MA;
		CB -= MB;
		CC -= MC;
		CD -= MD;
		CE -= ME;
		CF -= MF;

		// SWAP_BC -> integrated into WRITE_STATE

		// INCR_W
		W ++;

		// WRITE_STATE
		A[0] = A0;
		A[1] = A1;
		A[2] = A2;
		A[3] = A3;
		A[4] = A4;
		A[5] = A5;
		A[6] = A6;
		A[7] = A7;
		A[8] = A8;
		A[9] = A9;
		A[10] = AA;
		A[11] = AB;

		B[0] = C0;
		B[1] = C1;
		B[2] = C2;
		B[3] = C3;
		B[4] = C4;
		B[5] = C5;
		B[6] = C6;
		B[7] = C7;
		B[8] = C8;
		B[9] = C9;
		B[10] = CA;
		B[11] = CB;
		B[12] = CC;
		B[13] = CD;
		B[14] = CE;
		B[15] = CF;

		C[0] = B0;
		C[1] = B1;
		C[2] = B2;
		C[3] = B3;
		C[4] = B4;
		C[5] = B5;
		C[6] = B6;
		C[7] = B7;
		C[8] = B8;
		C[9] = B9;
		C[10] = BA;
		C[11] = BB;
		C[12] = BC;
		C[13] = BD;
		C[14] = BE;
		C[15] = BF;
	}

	private static final byte[] padData = {
		(byte)0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	/** @see DigestEngine */
	protected void doPadding(byte[] buf, int off)
	{
		/*
		 * This one triggers an additional call to processBlock().
		 * We set the output buffer in the relevant local variable,
		 * which triggers the adequate behaviour.
		 */
		outBuf = buf;
		outOff = off;
		update(padData, 0, 64 - flush());
		outBuf = null;
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		A = new int[12];
		B = new int[16];
		C = new int[16];
		outTmp = new byte[64];
		Ainit = getInitA();
		Binit = getInitB();
		Cinit = getInitC();
		doReset();
	}

	/**
	 * Get the initial values for {@code A[]} (12 values).
	 *
	 * @return  the {@code A[]} initial values
	 */
	abstract int[] getInitA();

	/**
	 * Get the initial values for {@code B[]} (16 values).
	 *
	 * @return  the {@code B[]} initial values
	 */
	abstract int[] getInitB();

	/**
	 * Get the initial values for {@code C[]} (16 values).
	 *
	 * @return  the {@code C[]} initial values
	 */
	abstract int[] getInitC();

	/** @see Digest */
	public int getBlockLength()
	{
		return 64;
	}

	private final void doReset()
	{
		System.arraycopy(Ainit, 0, A, 0, 12);
		System.arraycopy(Binit, 0, B, 0, 16);
		System.arraycopy(Cinit, 0, C, 0, 16);
		W = 1;
	}

	/** @see DigestEngine */
	protected Digest copyState(SHABALCore dst)
	{
		System.arraycopy(A, 0, dst.A, 0, 12);
		System.arraycopy(B, 0, dst.B, 0, 16);
		System.arraycopy(C, 0, dst.C, 0, 16);
		dst.W = W;
		return super.copyState(dst);
	}
}
