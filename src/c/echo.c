/* $Id: echo.c 173 2010-05-07 15:51:12Z tp $ */
/*
 * ECHO implementation.
 *
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
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stddef.h>
#include <string.h>
#include <limits.h>

#include "sph_echo.h"

#if defined SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_ECHO
#define SPH_SMALL_FOOTPRINT_ECHO   1
#endif

/*
 * Some measures tend to show that the 64-bit implementation offers
 * better performance only on a "64-bit architectures", those which have
 * actual 64-bit registers.
 */
#if !defined SPH_ECHO_64 && defined SPH_64_TRUE
#define SPH_ECHO_64   1
#endif

/*
 * We can use a 64-bit implementation only if a 64-bit type is available.
 */
#if !defined SPH_64
#undef SPH_ECHO_64
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

#define T32   SPH_T32
#define C32   SPH_C32
#ifdef SPH_64
#define C64   SPH_C64
#endif

/*
 * The AES*[] tables allow us to perform a fast evaluation of an AES
 * round; table AESi[] combines SubBytes for a byte at row i, and
 * MixColumns for the column where that byte goes after ShiftRows.
 */

static const sph_u32 AES0[256] = {
	C32(0xA56363C6), C32(0x847C7CF8), C32(0x997777EE), C32(0x8D7B7BF6),
	C32(0x0DF2F2FF), C32(0xBD6B6BD6), C32(0xB16F6FDE), C32(0x54C5C591),
	C32(0x50303060), C32(0x03010102), C32(0xA96767CE), C32(0x7D2B2B56),
	C32(0x19FEFEE7), C32(0x62D7D7B5), C32(0xE6ABAB4D), C32(0x9A7676EC),
	C32(0x45CACA8F), C32(0x9D82821F), C32(0x40C9C989), C32(0x877D7DFA),
	C32(0x15FAFAEF), C32(0xEB5959B2), C32(0xC947478E), C32(0x0BF0F0FB),
	C32(0xECADAD41), C32(0x67D4D4B3), C32(0xFDA2A25F), C32(0xEAAFAF45),
	C32(0xBF9C9C23), C32(0xF7A4A453), C32(0x967272E4), C32(0x5BC0C09B),
	C32(0xC2B7B775), C32(0x1CFDFDE1), C32(0xAE93933D), C32(0x6A26264C),
	C32(0x5A36366C), C32(0x413F3F7E), C32(0x02F7F7F5), C32(0x4FCCCC83),
	C32(0x5C343468), C32(0xF4A5A551), C32(0x34E5E5D1), C32(0x08F1F1F9),
	C32(0x937171E2), C32(0x73D8D8AB), C32(0x53313162), C32(0x3F15152A),
	C32(0x0C040408), C32(0x52C7C795), C32(0x65232346), C32(0x5EC3C39D),
	C32(0x28181830), C32(0xA1969637), C32(0x0F05050A), C32(0xB59A9A2F),
	C32(0x0907070E), C32(0x36121224), C32(0x9B80801B), C32(0x3DE2E2DF),
	C32(0x26EBEBCD), C32(0x6927274E), C32(0xCDB2B27F), C32(0x9F7575EA),
	C32(0x1B090912), C32(0x9E83831D), C32(0x742C2C58), C32(0x2E1A1A34),
	C32(0x2D1B1B36), C32(0xB26E6EDC), C32(0xEE5A5AB4), C32(0xFBA0A05B),
	C32(0xF65252A4), C32(0x4D3B3B76), C32(0x61D6D6B7), C32(0xCEB3B37D),
	C32(0x7B292952), C32(0x3EE3E3DD), C32(0x712F2F5E), C32(0x97848413),
	C32(0xF55353A6), C32(0x68D1D1B9), C32(0x00000000), C32(0x2CEDEDC1),
	C32(0x60202040), C32(0x1FFCFCE3), C32(0xC8B1B179), C32(0xED5B5BB6),
	C32(0xBE6A6AD4), C32(0x46CBCB8D), C32(0xD9BEBE67), C32(0x4B393972),
	C32(0xDE4A4A94), C32(0xD44C4C98), C32(0xE85858B0), C32(0x4ACFCF85),
	C32(0x6BD0D0BB), C32(0x2AEFEFC5), C32(0xE5AAAA4F), C32(0x16FBFBED),
	C32(0xC5434386), C32(0xD74D4D9A), C32(0x55333366), C32(0x94858511),
	C32(0xCF45458A), C32(0x10F9F9E9), C32(0x06020204), C32(0x817F7FFE),
	C32(0xF05050A0), C32(0x443C3C78), C32(0xBA9F9F25), C32(0xE3A8A84B),
	C32(0xF35151A2), C32(0xFEA3A35D), C32(0xC0404080), C32(0x8A8F8F05),
	C32(0xAD92923F), C32(0xBC9D9D21), C32(0x48383870), C32(0x04F5F5F1),
	C32(0xDFBCBC63), C32(0xC1B6B677), C32(0x75DADAAF), C32(0x63212142),
	C32(0x30101020), C32(0x1AFFFFE5), C32(0x0EF3F3FD), C32(0x6DD2D2BF),
	C32(0x4CCDCD81), C32(0x140C0C18), C32(0x35131326), C32(0x2FECECC3),
	C32(0xE15F5FBE), C32(0xA2979735), C32(0xCC444488), C32(0x3917172E),
	C32(0x57C4C493), C32(0xF2A7A755), C32(0x827E7EFC), C32(0x473D3D7A),
	C32(0xAC6464C8), C32(0xE75D5DBA), C32(0x2B191932), C32(0x957373E6),
	C32(0xA06060C0), C32(0x98818119), C32(0xD14F4F9E), C32(0x7FDCDCA3),
	C32(0x66222244), C32(0x7E2A2A54), C32(0xAB90903B), C32(0x8388880B),
	C32(0xCA46468C), C32(0x29EEEEC7), C32(0xD3B8B86B), C32(0x3C141428),
	C32(0x79DEDEA7), C32(0xE25E5EBC), C32(0x1D0B0B16), C32(0x76DBDBAD),
	C32(0x3BE0E0DB), C32(0x56323264), C32(0x4E3A3A74), C32(0x1E0A0A14),
	C32(0xDB494992), C32(0x0A06060C), C32(0x6C242448), C32(0xE45C5CB8),
	C32(0x5DC2C29F), C32(0x6ED3D3BD), C32(0xEFACAC43), C32(0xA66262C4),
	C32(0xA8919139), C32(0xA4959531), C32(0x37E4E4D3), C32(0x8B7979F2),
	C32(0x32E7E7D5), C32(0x43C8C88B), C32(0x5937376E), C32(0xB76D6DDA),
	C32(0x8C8D8D01), C32(0x64D5D5B1), C32(0xD24E4E9C), C32(0xE0A9A949),
	C32(0xB46C6CD8), C32(0xFA5656AC), C32(0x07F4F4F3), C32(0x25EAEACF),
	C32(0xAF6565CA), C32(0x8E7A7AF4), C32(0xE9AEAE47), C32(0x18080810),
	C32(0xD5BABA6F), C32(0x887878F0), C32(0x6F25254A), C32(0x722E2E5C),
	C32(0x241C1C38), C32(0xF1A6A657), C32(0xC7B4B473), C32(0x51C6C697),
	C32(0x23E8E8CB), C32(0x7CDDDDA1), C32(0x9C7474E8), C32(0x211F1F3E),
	C32(0xDD4B4B96), C32(0xDCBDBD61), C32(0x868B8B0D), C32(0x858A8A0F),
	C32(0x907070E0), C32(0x423E3E7C), C32(0xC4B5B571), C32(0xAA6666CC),
	C32(0xD8484890), C32(0x05030306), C32(0x01F6F6F7), C32(0x120E0E1C),
	C32(0xA36161C2), C32(0x5F35356A), C32(0xF95757AE), C32(0xD0B9B969),
	C32(0x91868617), C32(0x58C1C199), C32(0x271D1D3A), C32(0xB99E9E27),
	C32(0x38E1E1D9), C32(0x13F8F8EB), C32(0xB398982B), C32(0x33111122),
	C32(0xBB6969D2), C32(0x70D9D9A9), C32(0x898E8E07), C32(0xA7949433),
	C32(0xB69B9B2D), C32(0x221E1E3C), C32(0x92878715), C32(0x20E9E9C9),
	C32(0x49CECE87), C32(0xFF5555AA), C32(0x78282850), C32(0x7ADFDFA5),
	C32(0x8F8C8C03), C32(0xF8A1A159), C32(0x80898909), C32(0x170D0D1A),
	C32(0xDABFBF65), C32(0x31E6E6D7), C32(0xC6424284), C32(0xB86868D0),
	C32(0xC3414182), C32(0xB0999929), C32(0x772D2D5A), C32(0x110F0F1E),
	C32(0xCBB0B07B), C32(0xFC5454A8), C32(0xD6BBBB6D), C32(0x3A16162C)
};

static const sph_u32 AES1[256] = {
	C32(0x6363C6A5), C32(0x7C7CF884), C32(0x7777EE99), C32(0x7B7BF68D),
	C32(0xF2F2FF0D), C32(0x6B6BD6BD), C32(0x6F6FDEB1), C32(0xC5C59154),
	C32(0x30306050), C32(0x01010203), C32(0x6767CEA9), C32(0x2B2B567D),
	C32(0xFEFEE719), C32(0xD7D7B562), C32(0xABAB4DE6), C32(0x7676EC9A),
	C32(0xCACA8F45), C32(0x82821F9D), C32(0xC9C98940), C32(0x7D7DFA87),
	C32(0xFAFAEF15), C32(0x5959B2EB), C32(0x47478EC9), C32(0xF0F0FB0B),
	C32(0xADAD41EC), C32(0xD4D4B367), C32(0xA2A25FFD), C32(0xAFAF45EA),
	C32(0x9C9C23BF), C32(0xA4A453F7), C32(0x7272E496), C32(0xC0C09B5B),
	C32(0xB7B775C2), C32(0xFDFDE11C), C32(0x93933DAE), C32(0x26264C6A),
	C32(0x36366C5A), C32(0x3F3F7E41), C32(0xF7F7F502), C32(0xCCCC834F),
	C32(0x3434685C), C32(0xA5A551F4), C32(0xE5E5D134), C32(0xF1F1F908),
	C32(0x7171E293), C32(0xD8D8AB73), C32(0x31316253), C32(0x15152A3F),
	C32(0x0404080C), C32(0xC7C79552), C32(0x23234665), C32(0xC3C39D5E),
	C32(0x18183028), C32(0x969637A1), C32(0x05050A0F), C32(0x9A9A2FB5),
	C32(0x07070E09), C32(0x12122436), C32(0x80801B9B), C32(0xE2E2DF3D),
	C32(0xEBEBCD26), C32(0x27274E69), C32(0xB2B27FCD), C32(0x7575EA9F),
	C32(0x0909121B), C32(0x83831D9E), C32(0x2C2C5874), C32(0x1A1A342E),
	C32(0x1B1B362D), C32(0x6E6EDCB2), C32(0x5A5AB4EE), C32(0xA0A05BFB),
	C32(0x5252A4F6), C32(0x3B3B764D), C32(0xD6D6B761), C32(0xB3B37DCE),
	C32(0x2929527B), C32(0xE3E3DD3E), C32(0x2F2F5E71), C32(0x84841397),
	C32(0x5353A6F5), C32(0xD1D1B968), C32(0x00000000), C32(0xEDEDC12C),
	C32(0x20204060), C32(0xFCFCE31F), C32(0xB1B179C8), C32(0x5B5BB6ED),
	C32(0x6A6AD4BE), C32(0xCBCB8D46), C32(0xBEBE67D9), C32(0x3939724B),
	C32(0x4A4A94DE), C32(0x4C4C98D4), C32(0x5858B0E8), C32(0xCFCF854A),
	C32(0xD0D0BB6B), C32(0xEFEFC52A), C32(0xAAAA4FE5), C32(0xFBFBED16),
	C32(0x434386C5), C32(0x4D4D9AD7), C32(0x33336655), C32(0x85851194),
	C32(0x45458ACF), C32(0xF9F9E910), C32(0x02020406), C32(0x7F7FFE81),
	C32(0x5050A0F0), C32(0x3C3C7844), C32(0x9F9F25BA), C32(0xA8A84BE3),
	C32(0x5151A2F3), C32(0xA3A35DFE), C32(0x404080C0), C32(0x8F8F058A),
	C32(0x92923FAD), C32(0x9D9D21BC), C32(0x38387048), C32(0xF5F5F104),
	C32(0xBCBC63DF), C32(0xB6B677C1), C32(0xDADAAF75), C32(0x21214263),
	C32(0x10102030), C32(0xFFFFE51A), C32(0xF3F3FD0E), C32(0xD2D2BF6D),
	C32(0xCDCD814C), C32(0x0C0C1814), C32(0x13132635), C32(0xECECC32F),
	C32(0x5F5FBEE1), C32(0x979735A2), C32(0x444488CC), C32(0x17172E39),
	C32(0xC4C49357), C32(0xA7A755F2), C32(0x7E7EFC82), C32(0x3D3D7A47),
	C32(0x6464C8AC), C32(0x5D5DBAE7), C32(0x1919322B), C32(0x7373E695),
	C32(0x6060C0A0), C32(0x81811998), C32(0x4F4F9ED1), C32(0xDCDCA37F),
	C32(0x22224466), C32(0x2A2A547E), C32(0x90903BAB), C32(0x88880B83),
	C32(0x46468CCA), C32(0xEEEEC729), C32(0xB8B86BD3), C32(0x1414283C),
	C32(0xDEDEA779), C32(0x5E5EBCE2), C32(0x0B0B161D), C32(0xDBDBAD76),
	C32(0xE0E0DB3B), C32(0x32326456), C32(0x3A3A744E), C32(0x0A0A141E),
	C32(0x494992DB), C32(0x06060C0A), C32(0x2424486C), C32(0x5C5CB8E4),
	C32(0xC2C29F5D), C32(0xD3D3BD6E), C32(0xACAC43EF), C32(0x6262C4A6),
	C32(0x919139A8), C32(0x959531A4), C32(0xE4E4D337), C32(0x7979F28B),
	C32(0xE7E7D532), C32(0xC8C88B43), C32(0x37376E59), C32(0x6D6DDAB7),
	C32(0x8D8D018C), C32(0xD5D5B164), C32(0x4E4E9CD2), C32(0xA9A949E0),
	C32(0x6C6CD8B4), C32(0x5656ACFA), C32(0xF4F4F307), C32(0xEAEACF25),
	C32(0x6565CAAF), C32(0x7A7AF48E), C32(0xAEAE47E9), C32(0x08081018),
	C32(0xBABA6FD5), C32(0x7878F088), C32(0x25254A6F), C32(0x2E2E5C72),
	C32(0x1C1C3824), C32(0xA6A657F1), C32(0xB4B473C7), C32(0xC6C69751),
	C32(0xE8E8CB23), C32(0xDDDDA17C), C32(0x7474E89C), C32(0x1F1F3E21),
	C32(0x4B4B96DD), C32(0xBDBD61DC), C32(0x8B8B0D86), C32(0x8A8A0F85),
	C32(0x7070E090), C32(0x3E3E7C42), C32(0xB5B571C4), C32(0x6666CCAA),
	C32(0x484890D8), C32(0x03030605), C32(0xF6F6F701), C32(0x0E0E1C12),
	C32(0x6161C2A3), C32(0x35356A5F), C32(0x5757AEF9), C32(0xB9B969D0),
	C32(0x86861791), C32(0xC1C19958), C32(0x1D1D3A27), C32(0x9E9E27B9),
	C32(0xE1E1D938), C32(0xF8F8EB13), C32(0x98982BB3), C32(0x11112233),
	C32(0x6969D2BB), C32(0xD9D9A970), C32(0x8E8E0789), C32(0x949433A7),
	C32(0x9B9B2DB6), C32(0x1E1E3C22), C32(0x87871592), C32(0xE9E9C920),
	C32(0xCECE8749), C32(0x5555AAFF), C32(0x28285078), C32(0xDFDFA57A),
	C32(0x8C8C038F), C32(0xA1A159F8), C32(0x89890980), C32(0x0D0D1A17),
	C32(0xBFBF65DA), C32(0xE6E6D731), C32(0x424284C6), C32(0x6868D0B8),
	C32(0x414182C3), C32(0x999929B0), C32(0x2D2D5A77), C32(0x0F0F1E11),
	C32(0xB0B07BCB), C32(0x5454A8FC), C32(0xBBBB6DD6), C32(0x16162C3A)
};

static const sph_u32 AES2[256] = {
	C32(0x63C6A563), C32(0x7CF8847C), C32(0x77EE9977), C32(0x7BF68D7B),
	C32(0xF2FF0DF2), C32(0x6BD6BD6B), C32(0x6FDEB16F), C32(0xC59154C5),
	C32(0x30605030), C32(0x01020301), C32(0x67CEA967), C32(0x2B567D2B),
	C32(0xFEE719FE), C32(0xD7B562D7), C32(0xAB4DE6AB), C32(0x76EC9A76),
	C32(0xCA8F45CA), C32(0x821F9D82), C32(0xC98940C9), C32(0x7DFA877D),
	C32(0xFAEF15FA), C32(0x59B2EB59), C32(0x478EC947), C32(0xF0FB0BF0),
	C32(0xAD41ECAD), C32(0xD4B367D4), C32(0xA25FFDA2), C32(0xAF45EAAF),
	C32(0x9C23BF9C), C32(0xA453F7A4), C32(0x72E49672), C32(0xC09B5BC0),
	C32(0xB775C2B7), C32(0xFDE11CFD), C32(0x933DAE93), C32(0x264C6A26),
	C32(0x366C5A36), C32(0x3F7E413F), C32(0xF7F502F7), C32(0xCC834FCC),
	C32(0x34685C34), C32(0xA551F4A5), C32(0xE5D134E5), C32(0xF1F908F1),
	C32(0x71E29371), C32(0xD8AB73D8), C32(0x31625331), C32(0x152A3F15),
	C32(0x04080C04), C32(0xC79552C7), C32(0x23466523), C32(0xC39D5EC3),
	C32(0x18302818), C32(0x9637A196), C32(0x050A0F05), C32(0x9A2FB59A),
	C32(0x070E0907), C32(0x12243612), C32(0x801B9B80), C32(0xE2DF3DE2),
	C32(0xEBCD26EB), C32(0x274E6927), C32(0xB27FCDB2), C32(0x75EA9F75),
	C32(0x09121B09), C32(0x831D9E83), C32(0x2C58742C), C32(0x1A342E1A),
	C32(0x1B362D1B), C32(0x6EDCB26E), C32(0x5AB4EE5A), C32(0xA05BFBA0),
	C32(0x52A4F652), C32(0x3B764D3B), C32(0xD6B761D6), C32(0xB37DCEB3),
	C32(0x29527B29), C32(0xE3DD3EE3), C32(0x2F5E712F), C32(0x84139784),
	C32(0x53A6F553), C32(0xD1B968D1), C32(0x00000000), C32(0xEDC12CED),
	C32(0x20406020), C32(0xFCE31FFC), C32(0xB179C8B1), C32(0x5BB6ED5B),
	C32(0x6AD4BE6A), C32(0xCB8D46CB), C32(0xBE67D9BE), C32(0x39724B39),
	C32(0x4A94DE4A), C32(0x4C98D44C), C32(0x58B0E858), C32(0xCF854ACF),
	C32(0xD0BB6BD0), C32(0xEFC52AEF), C32(0xAA4FE5AA), C32(0xFBED16FB),
	C32(0x4386C543), C32(0x4D9AD74D), C32(0x33665533), C32(0x85119485),
	C32(0x458ACF45), C32(0xF9E910F9), C32(0x02040602), C32(0x7FFE817F),
	C32(0x50A0F050), C32(0x3C78443C), C32(0x9F25BA9F), C32(0xA84BE3A8),
	C32(0x51A2F351), C32(0xA35DFEA3), C32(0x4080C040), C32(0x8F058A8F),
	C32(0x923FAD92), C32(0x9D21BC9D), C32(0x38704838), C32(0xF5F104F5),
	C32(0xBC63DFBC), C32(0xB677C1B6), C32(0xDAAF75DA), C32(0x21426321),
	C32(0x10203010), C32(0xFFE51AFF), C32(0xF3FD0EF3), C32(0xD2BF6DD2),
	C32(0xCD814CCD), C32(0x0C18140C), C32(0x13263513), C32(0xECC32FEC),
	C32(0x5FBEE15F), C32(0x9735A297), C32(0x4488CC44), C32(0x172E3917),
	C32(0xC49357C4), C32(0xA755F2A7), C32(0x7EFC827E), C32(0x3D7A473D),
	C32(0x64C8AC64), C32(0x5DBAE75D), C32(0x19322B19), C32(0x73E69573),
	C32(0x60C0A060), C32(0x81199881), C32(0x4F9ED14F), C32(0xDCA37FDC),
	C32(0x22446622), C32(0x2A547E2A), C32(0x903BAB90), C32(0x880B8388),
	C32(0x468CCA46), C32(0xEEC729EE), C32(0xB86BD3B8), C32(0x14283C14),
	C32(0xDEA779DE), C32(0x5EBCE25E), C32(0x0B161D0B), C32(0xDBAD76DB),
	C32(0xE0DB3BE0), C32(0x32645632), C32(0x3A744E3A), C32(0x0A141E0A),
	C32(0x4992DB49), C32(0x060C0A06), C32(0x24486C24), C32(0x5CB8E45C),
	C32(0xC29F5DC2), C32(0xD3BD6ED3), C32(0xAC43EFAC), C32(0x62C4A662),
	C32(0x9139A891), C32(0x9531A495), C32(0xE4D337E4), C32(0x79F28B79),
	C32(0xE7D532E7), C32(0xC88B43C8), C32(0x376E5937), C32(0x6DDAB76D),
	C32(0x8D018C8D), C32(0xD5B164D5), C32(0x4E9CD24E), C32(0xA949E0A9),
	C32(0x6CD8B46C), C32(0x56ACFA56), C32(0xF4F307F4), C32(0xEACF25EA),
	C32(0x65CAAF65), C32(0x7AF48E7A), C32(0xAE47E9AE), C32(0x08101808),
	C32(0xBA6FD5BA), C32(0x78F08878), C32(0x254A6F25), C32(0x2E5C722E),
	C32(0x1C38241C), C32(0xA657F1A6), C32(0xB473C7B4), C32(0xC69751C6),
	C32(0xE8CB23E8), C32(0xDDA17CDD), C32(0x74E89C74), C32(0x1F3E211F),
	C32(0x4B96DD4B), C32(0xBD61DCBD), C32(0x8B0D868B), C32(0x8A0F858A),
	C32(0x70E09070), C32(0x3E7C423E), C32(0xB571C4B5), C32(0x66CCAA66),
	C32(0x4890D848), C32(0x03060503), C32(0xF6F701F6), C32(0x0E1C120E),
	C32(0x61C2A361), C32(0x356A5F35), C32(0x57AEF957), C32(0xB969D0B9),
	C32(0x86179186), C32(0xC19958C1), C32(0x1D3A271D), C32(0x9E27B99E),
	C32(0xE1D938E1), C32(0xF8EB13F8), C32(0x982BB398), C32(0x11223311),
	C32(0x69D2BB69), C32(0xD9A970D9), C32(0x8E07898E), C32(0x9433A794),
	C32(0x9B2DB69B), C32(0x1E3C221E), C32(0x87159287), C32(0xE9C920E9),
	C32(0xCE8749CE), C32(0x55AAFF55), C32(0x28507828), C32(0xDFA57ADF),
	C32(0x8C038F8C), C32(0xA159F8A1), C32(0x89098089), C32(0x0D1A170D),
	C32(0xBF65DABF), C32(0xE6D731E6), C32(0x4284C642), C32(0x68D0B868),
	C32(0x4182C341), C32(0x9929B099), C32(0x2D5A772D), C32(0x0F1E110F),
	C32(0xB07BCBB0), C32(0x54A8FC54), C32(0xBB6DD6BB), C32(0x162C3A16)
};

static const sph_u32 AES3[256] = {
	C32(0xC6A56363), C32(0xF8847C7C), C32(0xEE997777), C32(0xF68D7B7B),
	C32(0xFF0DF2F2), C32(0xD6BD6B6B), C32(0xDEB16F6F), C32(0x9154C5C5),
	C32(0x60503030), C32(0x02030101), C32(0xCEA96767), C32(0x567D2B2B),
	C32(0xE719FEFE), C32(0xB562D7D7), C32(0x4DE6ABAB), C32(0xEC9A7676),
	C32(0x8F45CACA), C32(0x1F9D8282), C32(0x8940C9C9), C32(0xFA877D7D),
	C32(0xEF15FAFA), C32(0xB2EB5959), C32(0x8EC94747), C32(0xFB0BF0F0),
	C32(0x41ECADAD), C32(0xB367D4D4), C32(0x5FFDA2A2), C32(0x45EAAFAF),
	C32(0x23BF9C9C), C32(0x53F7A4A4), C32(0xE4967272), C32(0x9B5BC0C0),
	C32(0x75C2B7B7), C32(0xE11CFDFD), C32(0x3DAE9393), C32(0x4C6A2626),
	C32(0x6C5A3636), C32(0x7E413F3F), C32(0xF502F7F7), C32(0x834FCCCC),
	C32(0x685C3434), C32(0x51F4A5A5), C32(0xD134E5E5), C32(0xF908F1F1),
	C32(0xE2937171), C32(0xAB73D8D8), C32(0x62533131), C32(0x2A3F1515),
	C32(0x080C0404), C32(0x9552C7C7), C32(0x46652323), C32(0x9D5EC3C3),
	C32(0x30281818), C32(0x37A19696), C32(0x0A0F0505), C32(0x2FB59A9A),
	C32(0x0E090707), C32(0x24361212), C32(0x1B9B8080), C32(0xDF3DE2E2),
	C32(0xCD26EBEB), C32(0x4E692727), C32(0x7FCDB2B2), C32(0xEA9F7575),
	C32(0x121B0909), C32(0x1D9E8383), C32(0x58742C2C), C32(0x342E1A1A),
	C32(0x362D1B1B), C32(0xDCB26E6E), C32(0xB4EE5A5A), C32(0x5BFBA0A0),
	C32(0xA4F65252), C32(0x764D3B3B), C32(0xB761D6D6), C32(0x7DCEB3B3),
	C32(0x527B2929), C32(0xDD3EE3E3), C32(0x5E712F2F), C32(0x13978484),
	C32(0xA6F55353), C32(0xB968D1D1), C32(0x00000000), C32(0xC12CEDED),
	C32(0x40602020), C32(0xE31FFCFC), C32(0x79C8B1B1), C32(0xB6ED5B5B),
	C32(0xD4BE6A6A), C32(0x8D46CBCB), C32(0x67D9BEBE), C32(0x724B3939),
	C32(0x94DE4A4A), C32(0x98D44C4C), C32(0xB0E85858), C32(0x854ACFCF),
	C32(0xBB6BD0D0), C32(0xC52AEFEF), C32(0x4FE5AAAA), C32(0xED16FBFB),
	C32(0x86C54343), C32(0x9AD74D4D), C32(0x66553333), C32(0x11948585),
	C32(0x8ACF4545), C32(0xE910F9F9), C32(0x04060202), C32(0xFE817F7F),
	C32(0xA0F05050), C32(0x78443C3C), C32(0x25BA9F9F), C32(0x4BE3A8A8),
	C32(0xA2F35151), C32(0x5DFEA3A3), C32(0x80C04040), C32(0x058A8F8F),
	C32(0x3FAD9292), C32(0x21BC9D9D), C32(0x70483838), C32(0xF104F5F5),
	C32(0x63DFBCBC), C32(0x77C1B6B6), C32(0xAF75DADA), C32(0x42632121),
	C32(0x20301010), C32(0xE51AFFFF), C32(0xFD0EF3F3), C32(0xBF6DD2D2),
	C32(0x814CCDCD), C32(0x18140C0C), C32(0x26351313), C32(0xC32FECEC),
	C32(0xBEE15F5F), C32(0x35A29797), C32(0x88CC4444), C32(0x2E391717),
	C32(0x9357C4C4), C32(0x55F2A7A7), C32(0xFC827E7E), C32(0x7A473D3D),
	C32(0xC8AC6464), C32(0xBAE75D5D), C32(0x322B1919), C32(0xE6957373),
	C32(0xC0A06060), C32(0x19988181), C32(0x9ED14F4F), C32(0xA37FDCDC),
	C32(0x44662222), C32(0x547E2A2A), C32(0x3BAB9090), C32(0x0B838888),
	C32(0x8CCA4646), C32(0xC729EEEE), C32(0x6BD3B8B8), C32(0x283C1414),
	C32(0xA779DEDE), C32(0xBCE25E5E), C32(0x161D0B0B), C32(0xAD76DBDB),
	C32(0xDB3BE0E0), C32(0x64563232), C32(0x744E3A3A), C32(0x141E0A0A),
	C32(0x92DB4949), C32(0x0C0A0606), C32(0x486C2424), C32(0xB8E45C5C),
	C32(0x9F5DC2C2), C32(0xBD6ED3D3), C32(0x43EFACAC), C32(0xC4A66262),
	C32(0x39A89191), C32(0x31A49595), C32(0xD337E4E4), C32(0xF28B7979),
	C32(0xD532E7E7), C32(0x8B43C8C8), C32(0x6E593737), C32(0xDAB76D6D),
	C32(0x018C8D8D), C32(0xB164D5D5), C32(0x9CD24E4E), C32(0x49E0A9A9),
	C32(0xD8B46C6C), C32(0xACFA5656), C32(0xF307F4F4), C32(0xCF25EAEA),
	C32(0xCAAF6565), C32(0xF48E7A7A), C32(0x47E9AEAE), C32(0x10180808),
	C32(0x6FD5BABA), C32(0xF0887878), C32(0x4A6F2525), C32(0x5C722E2E),
	C32(0x38241C1C), C32(0x57F1A6A6), C32(0x73C7B4B4), C32(0x9751C6C6),
	C32(0xCB23E8E8), C32(0xA17CDDDD), C32(0xE89C7474), C32(0x3E211F1F),
	C32(0x96DD4B4B), C32(0x61DCBDBD), C32(0x0D868B8B), C32(0x0F858A8A),
	C32(0xE0907070), C32(0x7C423E3E), C32(0x71C4B5B5), C32(0xCCAA6666),
	C32(0x90D84848), C32(0x06050303), C32(0xF701F6F6), C32(0x1C120E0E),
	C32(0xC2A36161), C32(0x6A5F3535), C32(0xAEF95757), C32(0x69D0B9B9),
	C32(0x17918686), C32(0x9958C1C1), C32(0x3A271D1D), C32(0x27B99E9E),
	C32(0xD938E1E1), C32(0xEB13F8F8), C32(0x2BB39898), C32(0x22331111),
	C32(0xD2BB6969), C32(0xA970D9D9), C32(0x07898E8E), C32(0x33A79494),
	C32(0x2DB69B9B), C32(0x3C221E1E), C32(0x15928787), C32(0xC920E9E9),
	C32(0x8749CECE), C32(0xAAFF5555), C32(0x50782828), C32(0xA57ADFDF),
	C32(0x038F8C8C), C32(0x59F8A1A1), C32(0x09808989), C32(0x1A170D0D),
	C32(0x65DABFBF), C32(0xD731E6E6), C32(0x84C64242), C32(0xD0B86868),
	C32(0x82C34141), C32(0x29B09999), C32(0x5A772D2D), C32(0x1E110F0F),
	C32(0x7BCBB0B0), C32(0xA8FC5454), C32(0x6DD6BBBB), C32(0x2C3A1616)
};

#if SPH_ECHO_64

#define DECL_STATE_SMALL   \
	sph_u64 W[16][2];

#define DECL_STATE_BIG   \
	sph_u64 W[16][2];

#define INPUT_BLOCK_SMALL(sc)   do { \
		unsigned u; \
		memcpy(W, sc->u.Vb, 8 * sizeof(sph_u64)); \
		for (u = 0; u < 12; u ++) { \
			W[u + 4][0] = sph_dec64le_aligned( \
				sc->buf + 16 * u); \
			W[u + 4][1] = sph_dec64le_aligned( \
				sc->buf + 16 * u + 8); \
		} \
	} while (0)

#define INPUT_BLOCK_BIG(sc)   do { \
		unsigned u; \
		memcpy(W, sc->u.Vb, 16 * sizeof(sph_u64)); \
		for (u = 0; u < 8; u ++) { \
			W[u + 8][0] = sph_dec64le_aligned( \
				sc->buf + 16 * u); \
			W[u + 8][1] = sph_dec64le_aligned( \
				sc->buf + 16 * u + 8); \
		} \
	} while (0)

#if SPH_SMALL_FOOTPRINT_ECHO

static void
aes_2rounds_all(sph_u64 W[16][2],
	sph_u32 *pK0, sph_u32 *pK1, sph_u32 *pK2, sph_u32 *pK3)
{
	int n;
	sph_u32 K0 = *pK0;
	sph_u32 K1 = *pK1;
	sph_u32 K2 = *pK2;
	sph_u32 K3 = *pK3;

	for (n = 0; n < 16; n ++) {
		sph_u64 Wl = W[n][0];
		sph_u64 Wh = W[n][1];
		sph_u32 X0 = (sph_u32)Wl;
		sph_u32 X1 = (sph_u32)(Wl >> 32);
		sph_u32 X2 = (sph_u32)Wh;
		sph_u32 X3 = (sph_u32)(Wh >> 32);
		sph_u32 Y0 = AES0[X0 & 0xFF]
			^ AES1[(X1 >> 8) & 0xFF]
			^ AES2[(X2 >> 16) & 0xFF]
			^ AES3[(X3 >> 24) & 0xFF] ^ K0;
		sph_u32 Y1 = AES0[X1 & 0xFF]
			^ AES1[(X2 >> 8) & 0xFF]
			^ AES2[(X3 >> 16) & 0xFF]
			^ AES3[(X0 >> 24) & 0xFF] ^ K1;
		sph_u32 Y2 = AES0[X2 & 0xFF]
			^ AES1[(X3 >> 8) & 0xFF]
			^ AES2[(X0 >> 16) & 0xFF]
			^ AES3[(X1 >> 24) & 0xFF] ^ K2;
		sph_u32 Y3 = AES0[X3 & 0xFF]
			^ AES1[(X0 >> 8) & 0xFF]
			^ AES2[(X1 >> 16) & 0xFF]
			^ AES3[(X2 >> 24) & 0xFF] ^ K3;
		X0 = AES0[Y0 & 0xFF]
			^ AES1[(Y1 >> 8) & 0xFF]
			^ AES2[(Y2 >> 16) & 0xFF]
			^ AES3[(Y3 >> 24) & 0xFF];
		X1 = AES0[Y1 & 0xFF]
			^ AES1[(Y2 >> 8) & 0xFF]
			^ AES2[(Y3 >> 16) & 0xFF]
			^ AES3[(Y0 >> 24) & 0xFF];
		X2 = AES0[Y2 & 0xFF]
			^ AES1[(Y3 >> 8) & 0xFF]
			^ AES2[(Y0 >> 16) & 0xFF]
			^ AES3[(Y1 >> 24) & 0xFF];
		X3 = AES0[Y3 & 0xFF]
			^ AES1[(Y0 >> 8) & 0xFF]
			^ AES2[(Y1 >> 16) & 0xFF]
			^ AES3[(Y2 >> 24) & 0xFF];
		W[n][0] = (sph_u64)X0 | ((sph_u64)X1 << 32);
		W[n][1] = (sph_u64)X2 | ((sph_u64)X3 << 32);
		if ((K0 = T32(K0 + 1)) == 0) {
			if ((K1 = T32(K1 + 1)) == 0)
				if ((K2 = T32(K2 + 1)) == 0)
					K3 = T32(K3 + 1);
		}
	}
	*pK0 = K0;
	*pK1 = K1;
	*pK2 = K2;
	*pK3 = K3;
}

#define BIG_SUB_WORDS   do { \
		aes_2rounds_all(W, &K0, &K1, &K2, &K3); \
	} while (0)

#else

#define AES_2ROUNDS(X)   do { \
		sph_u32 X0 = (sph_u32)(X[0]); \
		sph_u32 X1 = (sph_u32)(X[0] >> 32); \
		sph_u32 X2 = (sph_u32)(X[1]); \
		sph_u32 X3 = (sph_u32)(X[1] >> 32); \
		sph_u32 Y0 = AES0[X0 & 0xFF] \
			^ AES1[(X1 >> 8) & 0xFF] \
			^ AES2[(X2 >> 16) & 0xFF] \
			^ AES3[(X3 >> 24) & 0xFF] ^ K0; \
		sph_u32 Y1 = AES0[X1 & 0xFF] \
			^ AES1[(X2 >> 8) & 0xFF] \
			^ AES2[(X3 >> 16) & 0xFF] \
			^ AES3[(X0 >> 24) & 0xFF] ^ K1; \
		sph_u32 Y2 = AES0[X2 & 0xFF] \
			^ AES1[(X3 >> 8) & 0xFF] \
			^ AES2[(X0 >> 16) & 0xFF] \
			^ AES3[(X1 >> 24) & 0xFF] ^ K2; \
		sph_u32 Y3 = AES0[X3 & 0xFF] \
			^ AES1[(X0 >> 8) & 0xFF] \
			^ AES2[(X1 >> 16) & 0xFF] \
			^ AES3[(X2 >> 24) & 0xFF] ^ K3; \
		X0 = AES0[Y0 & 0xFF] \
			^ AES1[(Y1 >> 8) & 0xFF] \
			^ AES2[(Y2 >> 16) & 0xFF] \
			^ AES3[(Y3 >> 24) & 0xFF]; \
		X1 = AES0[Y1 & 0xFF] \
			^ AES1[(Y2 >> 8) & 0xFF] \
			^ AES2[(Y3 >> 16) & 0xFF] \
			^ AES3[(Y0 >> 24) & 0xFF]; \
		X2 = AES0[Y2 & 0xFF] \
			^ AES1[(Y3 >> 8) & 0xFF] \
			^ AES2[(Y0 >> 16) & 0xFF] \
			^ AES3[(Y1 >> 24) & 0xFF]; \
		X3 = AES0[Y3 & 0xFF] \
			^ AES1[(Y0 >> 8) & 0xFF] \
			^ AES2[(Y1 >> 16) & 0xFF] \
			^ AES3[(Y2 >> 24) & 0xFF]; \
		X[0] = (sph_u64)X0 | ((sph_u64)X1 << 32); \
		X[1] = (sph_u64)X2 | ((sph_u64)X3 << 32); \
		if ((K0 = T32(K0 + 1)) == 0) { \
			if ((K1 = T32(K1 + 1)) == 0) \
				if ((K2 = T32(K2 + 1)) == 0) \
					K3 = T32(K3 + 1); \
		} \
	} while (0)

#define BIG_SUB_WORDS   do { \
		AES_2ROUNDS(W[ 0]); \
		AES_2ROUNDS(W[ 1]); \
		AES_2ROUNDS(W[ 2]); \
		AES_2ROUNDS(W[ 3]); \
		AES_2ROUNDS(W[ 4]); \
		AES_2ROUNDS(W[ 5]); \
		AES_2ROUNDS(W[ 6]); \
		AES_2ROUNDS(W[ 7]); \
		AES_2ROUNDS(W[ 8]); \
		AES_2ROUNDS(W[ 9]); \
		AES_2ROUNDS(W[10]); \
		AES_2ROUNDS(W[11]); \
		AES_2ROUNDS(W[12]); \
		AES_2ROUNDS(W[13]); \
		AES_2ROUNDS(W[14]); \
		AES_2ROUNDS(W[15]); \
	} while (0)

#endif

#define SHIFT_ROW1(a, b, c, d)   do { \
		sph_u64 tmp; \
		tmp = W[a][0]; \
		W[a][0] = W[b][0]; \
		W[b][0] = W[c][0]; \
		W[c][0] = W[d][0]; \
		W[d][0] = tmp; \
		tmp = W[a][1]; \
		W[a][1] = W[b][1]; \
		W[b][1] = W[c][1]; \
		W[c][1] = W[d][1]; \
		W[d][1] = tmp; \
	} while (0)

#define SHIFT_ROW2(a, b, c, d)   do { \
		sph_u64 tmp; \
		tmp = W[a][0]; \
		W[a][0] = W[c][0]; \
		W[c][0] = tmp; \
		tmp = W[b][0]; \
		W[b][0] = W[d][0]; \
		W[d][0] = tmp; \
		tmp = W[a][1]; \
		W[a][1] = W[c][1]; \
		W[c][1] = tmp; \
		tmp = W[b][1]; \
		W[b][1] = W[d][1]; \
		W[d][1] = tmp; \
	} while (0)

#define SHIFT_ROW3(a, b, c, d)   SHIFT_ROW1(d, c, b, a)

#define BIG_SHIFT_ROWS   do { \
		SHIFT_ROW1(1, 5, 9, 13); \
		SHIFT_ROW2(2, 6, 10, 14); \
		SHIFT_ROW3(3, 7, 11, 15); \
	} while (0)

#if SPH_SMALL_FOOTPRINT_ECHO

static void
mix_column(sph_u64 W[16][2], int ia, int ib, int ic, int id)
{
	int n;

	for (n = 0; n < 2; n ++) {
		sph_u64 a = W[ia][n];
		sph_u64 b = W[ib][n];
		sph_u64 c = W[ic][n];
		sph_u64 d = W[id][n];
		sph_u64 ab = a ^ b;
		sph_u64 bc = b ^ c;
		sph_u64 cd = c ^ d;
		sph_u64 abx = ((ab & C64(0x8080808080808080)) >> 7) * 27U
			^ ((ab & C64(0x7F7F7F7F7F7F7F7F)) << 1);
		sph_u64 bcx = ((bc & C64(0x8080808080808080)) >> 7) * 27U
			^ ((bc & C64(0x7F7F7F7F7F7F7F7F)) << 1);
		sph_u64 cdx = ((cd & C64(0x8080808080808080)) >> 7) * 27U
			^ ((cd & C64(0x7F7F7F7F7F7F7F7F)) << 1);
		W[ia][n] = abx ^ bc ^ d;
		W[ib][n] = bcx ^ a ^ cd;
		W[ic][n] = cdx ^ ab ^ d;
		W[id][n] = abx ^ bcx ^ cdx ^ ab ^ c;
	}
}

#define MIX_COLUMN(a, b, c, d)   mix_column(W, a, b, c, d)

#else

#define MIX_COLUMN1(ia, ib, ic, id, n)   do { \
		sph_u64 a = W[ia][n]; \
		sph_u64 b = W[ib][n]; \
		sph_u64 c = W[ic][n]; \
		sph_u64 d = W[id][n]; \
		sph_u64 ab = a ^ b; \
		sph_u64 bc = b ^ c; \
		sph_u64 cd = c ^ d; \
		sph_u64 abx = ((ab & C64(0x8080808080808080)) >> 7) * 27U \
			^ ((ab & C64(0x7F7F7F7F7F7F7F7F)) << 1); \
		sph_u64 bcx = ((bc & C64(0x8080808080808080)) >> 7) * 27U \
			^ ((bc & C64(0x7F7F7F7F7F7F7F7F)) << 1); \
		sph_u64 cdx = ((cd & C64(0x8080808080808080)) >> 7) * 27U \
			^ ((cd & C64(0x7F7F7F7F7F7F7F7F)) << 1); \
		W[ia][n] = abx ^ bc ^ d; \
		W[ib][n] = bcx ^ a ^ cd; \
		W[ic][n] = cdx ^ ab ^ d; \
		W[id][n] = abx ^ bcx ^ cdx ^ ab ^ c; \
	} while (0)

#define MIX_COLUMN(a, b, c, d)   do { \
		MIX_COLUMN1(a, b, c, d, 0); \
		MIX_COLUMN1(a, b, c, d, 1); \
	} while (0)

#endif

#define BIG_MIX_COLUMNS   do { \
		MIX_COLUMN(0, 1, 2, 3); \
		MIX_COLUMN(4, 5, 6, 7); \
		MIX_COLUMN(8, 9, 10, 11); \
		MIX_COLUMN(12, 13, 14, 15); \
	} while (0)

#define BIG_ROUND   do { \
		BIG_SUB_WORDS; \
		BIG_SHIFT_ROWS; \
		BIG_MIX_COLUMNS; \
	} while (0)

#define FINAL_SMALL   do { \
		unsigned u; \
		sph_u64 *VV = &sc->u.Vb[0][0]; \
		sph_u64 *WW = &W[0][0]; \
		for (u = 0; u < 8; u ++) { \
			VV[u] ^= sph_dec64le_aligned(sc->buf + (u * 8)) \
				^ sph_dec64le_aligned(sc->buf + (u * 8) + 64) \
				^ sph_dec64le_aligned(sc->buf + (u * 8) + 128) \
				^ WW[u] ^ WW[u + 8] \
				^ WW[u + 16] ^ WW[u + 24]; \
		} \
	} while (0)

#define FINAL_BIG   do { \
		unsigned u; \
		sph_u64 *VV = &sc->u.Vb[0][0]; \
		sph_u64 *WW = &W[0][0]; \
		for (u = 0; u < 16; u ++) { \
			VV[u] ^= sph_dec64le_aligned(sc->buf + (u * 8)) \
				^ WW[u] ^ WW[u + 16]; \
		} \
	} while (0)

#define COMPRESS_SMALL(sc)   do { \
		sph_u32 K0 = sc->C0; \
		sph_u32 K1 = sc->C1; \
		sph_u32 K2 = sc->C2; \
		sph_u32 K3 = sc->C3; \
		unsigned u; \
		INPUT_BLOCK_SMALL(sc); \
		for (u = 0; u < 8; u ++) { \
			BIG_ROUND; \
		} \
		FINAL_SMALL; \
	} while (0)

#define COMPRESS_BIG(sc)   do { \
		sph_u32 K0 = sc->C0; \
		sph_u32 K1 = sc->C1; \
		sph_u32 K2 = sc->C2; \
		sph_u32 K3 = sc->C3; \
		unsigned u; \
		INPUT_BLOCK_BIG(sc); \
		for (u = 0; u < 10; u ++) { \
			BIG_ROUND; \
		} \
		FINAL_BIG; \
	} while (0)

#else

#define DECL_STATE_SMALL   \
	sph_u32 W[16][4];

#define DECL_STATE_BIG   \
	sph_u32 W[16][4];

#define INPUT_BLOCK_SMALL(sc)   do { \
		unsigned u; \
		memcpy(W, sc->u.Vs, 16 * sizeof(sph_u32)); \
		for (u = 0; u < 12; u ++) { \
			W[u + 4][0] = sph_dec32le_aligned( \
				sc->buf + 16 * u); \
			W[u + 4][1] = sph_dec32le_aligned( \
				sc->buf + 16 * u + 4); \
			W[u + 4][2] = sph_dec32le_aligned( \
				sc->buf + 16 * u + 8); \
			W[u + 4][3] = sph_dec32le_aligned( \
				sc->buf + 16 * u + 12); \
		} \
	} while (0)

#define INPUT_BLOCK_BIG(sc)   do { \
		unsigned u; \
		memcpy(W, sc->u.Vs, 32 * sizeof(sph_u32)); \
		for (u = 0; u < 8; u ++) { \
			W[u + 8][0] = sph_dec32le_aligned( \
				sc->buf + 16 * u); \
			W[u + 8][1] = sph_dec32le_aligned( \
				sc->buf + 16 * u + 4); \
			W[u + 8][2] = sph_dec32le_aligned( \
				sc->buf + 16 * u + 8); \
			W[u + 8][3] = sph_dec32le_aligned( \
				sc->buf + 16 * u + 12); \
		} \
	} while (0)

#if SPH_SMALL_FOOTPRINT_ECHO

static void
aes_2rounds_all(sph_u32 W[16][4],
	sph_u32 *pK0, sph_u32 *pK1, sph_u32 *pK2, sph_u32 *pK3)
{
	int n;
	sph_u32 K0 = *pK0;
	sph_u32 K1 = *pK1;
	sph_u32 K2 = *pK2;
	sph_u32 K3 = *pK3;

	for (n = 0; n < 16; n ++) {
		sph_u32 *X = W[n];
		sph_u32 Y0 = AES0[X[0] & 0xFF]
			^ AES1[(X[1] >> 8) & 0xFF]
			^ AES2[(X[2] >> 16) & 0xFF]
			^ AES3[(X[3] >> 24) & 0xFF] ^ K0;
		sph_u32 Y1 = AES0[X[1] & 0xFF]
			^ AES1[(X[2] >> 8) & 0xFF]
			^ AES2[(X[3] >> 16) & 0xFF]
			^ AES3[(X[0] >> 24) & 0xFF] ^ K1;
		sph_u32 Y2 = AES0[X[2] & 0xFF]
			^ AES1[(X[3] >> 8) & 0xFF]
			^ AES2[(X[0] >> 16) & 0xFF]
			^ AES3[(X[1] >> 24) & 0xFF] ^ K2;
		sph_u32 Y3 = AES0[X[3] & 0xFF]
			^ AES1[(X[0] >> 8) & 0xFF]
			^ AES2[(X[1] >> 16) & 0xFF]
			^ AES3[(X[2] >> 24) & 0xFF] ^ K3;
		X[0] = AES0[Y0 & 0xFF]
			^ AES1[(Y1 >> 8) & 0xFF]
			^ AES2[(Y2 >> 16) & 0xFF]
			^ AES3[(Y3 >> 24) & 0xFF];
		X[1] = AES0[Y1 & 0xFF]
			^ AES1[(Y2 >> 8) & 0xFF]
			^ AES2[(Y3 >> 16) & 0xFF]
			^ AES3[(Y0 >> 24) & 0xFF];
		X[2] = AES0[Y2 & 0xFF]
			^ AES1[(Y3 >> 8) & 0xFF]
			^ AES2[(Y0 >> 16) & 0xFF]
			^ AES3[(Y1 >> 24) & 0xFF];
		X[3] = AES0[Y3 & 0xFF]
			^ AES1[(Y0 >> 8) & 0xFF]
			^ AES2[(Y1 >> 16) & 0xFF]
			^ AES3[(Y2 >> 24) & 0xFF];
		if ((K0 = T32(K0 + 1)) == 0) {
			if ((K1 = T32(K1 + 1)) == 0)
				if ((K2 = T32(K2 + 1)) == 0)
					K3 = T32(K3 + 1);
		}
	}
	*pK0 = K0;
	*pK1 = K1;
	*pK2 = K2;
	*pK3 = K3;
}

#define BIG_SUB_WORDS   do { \
		aes_2rounds_all(W, &K0, &K1, &K2, &K3); \
	} while (0)

#else

#define AES_2ROUNDS(X)   do { \
		sph_u32 Y0 = AES0[X[0] & 0xFF] \
			^ AES1[(X[1] >> 8) & 0xFF] \
			^ AES2[(X[2] >> 16) & 0xFF] \
			^ AES3[(X[3] >> 24) & 0xFF] ^ K0; \
		sph_u32 Y1 = AES0[X[1] & 0xFF] \
			^ AES1[(X[2] >> 8) & 0xFF] \
			^ AES2[(X[3] >> 16) & 0xFF] \
			^ AES3[(X[0] >> 24) & 0xFF] ^ K1; \
		sph_u32 Y2 = AES0[X[2] & 0xFF] \
			^ AES1[(X[3] >> 8) & 0xFF] \
			^ AES2[(X[0] >> 16) & 0xFF] \
			^ AES3[(X[1] >> 24) & 0xFF] ^ K2; \
		sph_u32 Y3 = AES0[X[3] & 0xFF] \
			^ AES1[(X[0] >> 8) & 0xFF] \
			^ AES2[(X[1] >> 16) & 0xFF] \
			^ AES3[(X[2] >> 24) & 0xFF] ^ K3; \
		X[0] = AES0[Y0 & 0xFF] \
			^ AES1[(Y1 >> 8) & 0xFF] \
			^ AES2[(Y2 >> 16) & 0xFF] \
			^ AES3[(Y3 >> 24) & 0xFF]; \
		X[1] = AES0[Y1 & 0xFF] \
			^ AES1[(Y2 >> 8) & 0xFF] \
			^ AES2[(Y3 >> 16) & 0xFF] \
			^ AES3[(Y0 >> 24) & 0xFF]; \
		X[2] = AES0[Y2 & 0xFF] \
			^ AES1[(Y3 >> 8) & 0xFF] \
			^ AES2[(Y0 >> 16) & 0xFF] \
			^ AES3[(Y1 >> 24) & 0xFF]; \
		X[3] = AES0[Y3 & 0xFF] \
			^ AES1[(Y0 >> 8) & 0xFF] \
			^ AES2[(Y1 >> 16) & 0xFF] \
			^ AES3[(Y2 >> 24) & 0xFF]; \
		if ((K0 = T32(K0 + 1)) == 0) { \
			if ((K1 = T32(K1 + 1)) == 0) \
				if ((K2 = T32(K2 + 1)) == 0) \
					K3 = T32(K3 + 1); \
		} \
	} while (0)

#define BIG_SUB_WORDS   do { \
		AES_2ROUNDS(W[ 0]); \
		AES_2ROUNDS(W[ 1]); \
		AES_2ROUNDS(W[ 2]); \
		AES_2ROUNDS(W[ 3]); \
		AES_2ROUNDS(W[ 4]); \
		AES_2ROUNDS(W[ 5]); \
		AES_2ROUNDS(W[ 6]); \
		AES_2ROUNDS(W[ 7]); \
		AES_2ROUNDS(W[ 8]); \
		AES_2ROUNDS(W[ 9]); \
		AES_2ROUNDS(W[10]); \
		AES_2ROUNDS(W[11]); \
		AES_2ROUNDS(W[12]); \
		AES_2ROUNDS(W[13]); \
		AES_2ROUNDS(W[14]); \
		AES_2ROUNDS(W[15]); \
	} while (0)

#endif

#define SHIFT_ROW1(a, b, c, d)   do { \
		sph_u32 tmp; \
		tmp = W[a][0]; \
		W[a][0] = W[b][0]; \
		W[b][0] = W[c][0]; \
		W[c][0] = W[d][0]; \
		W[d][0] = tmp; \
		tmp = W[a][1]; \
		W[a][1] = W[b][1]; \
		W[b][1] = W[c][1]; \
		W[c][1] = W[d][1]; \
		W[d][1] = tmp; \
		tmp = W[a][2]; \
		W[a][2] = W[b][2]; \
		W[b][2] = W[c][2]; \
		W[c][2] = W[d][2]; \
		W[d][2] = tmp; \
		tmp = W[a][3]; \
		W[a][3] = W[b][3]; \
		W[b][3] = W[c][3]; \
		W[c][3] = W[d][3]; \
		W[d][3] = tmp; \
	} while (0)

#define SHIFT_ROW2(a, b, c, d)   do { \
		sph_u32 tmp; \
		tmp = W[a][0]; \
		W[a][0] = W[c][0]; \
		W[c][0] = tmp; \
		tmp = W[b][0]; \
		W[b][0] = W[d][0]; \
		W[d][0] = tmp; \
		tmp = W[a][1]; \
		W[a][1] = W[c][1]; \
		W[c][1] = tmp; \
		tmp = W[b][1]; \
		W[b][1] = W[d][1]; \
		W[d][1] = tmp; \
		tmp = W[a][2]; \
		W[a][2] = W[c][2]; \
		W[c][2] = tmp; \
		tmp = W[b][2]; \
		W[b][2] = W[d][2]; \
		W[d][2] = tmp; \
		tmp = W[a][3]; \
		W[a][3] = W[c][3]; \
		W[c][3] = tmp; \
		tmp = W[b][3]; \
		W[b][3] = W[d][3]; \
		W[d][3] = tmp; \
	} while (0)

#define SHIFT_ROW3(a, b, c, d)   SHIFT_ROW1(d, c, b, a)

#define BIG_SHIFT_ROWS   do { \
		SHIFT_ROW1(1, 5, 9, 13); \
		SHIFT_ROW2(2, 6, 10, 14); \
		SHIFT_ROW3(3, 7, 11, 15); \
	} while (0)

#if SPH_SMALL_FOOTPRINT_ECHO

static void
mix_column(sph_u32 W[16][4], int ia, int ib, int ic, int id)
{
	int n;

	for (n = 0; n < 4; n ++) {
		sph_u32 a = W[ia][n];
		sph_u32 b = W[ib][n];
		sph_u32 c = W[ic][n];
		sph_u32 d = W[id][n];
		sph_u32 ab = a ^ b;
		sph_u32 bc = b ^ c;
		sph_u32 cd = c ^ d;
		sph_u32 abx = ((ab & C32(0x80808080)) >> 7) * 27U
			^ ((ab & C32(0x7F7F7F7F)) << 1);
		sph_u32 bcx = ((bc & C32(0x80808080)) >> 7) * 27U
			^ ((bc & C32(0x7F7F7F7F)) << 1);
		sph_u32 cdx = ((cd & C32(0x80808080)) >> 7) * 27U
			^ ((cd & C32(0x7F7F7F7F)) << 1);
		W[ia][n] = abx ^ bc ^ d;
		W[ib][n] = bcx ^ a ^ cd;
		W[ic][n] = cdx ^ ab ^ d;
		W[id][n] = abx ^ bcx ^ cdx ^ ab ^ c;
	}
}

#define MIX_COLUMN(a, b, c, d)   mix_column(W, a, b, c, d)

#else

#define MIX_COLUMN1(ia, ib, ic, id, n)   do { \
		sph_u32 a = W[ia][n]; \
		sph_u32 b = W[ib][n]; \
		sph_u32 c = W[ic][n]; \
		sph_u32 d = W[id][n]; \
		sph_u32 ab = a ^ b; \
		sph_u32 bc = b ^ c; \
		sph_u32 cd = c ^ d; \
		sph_u32 abx = ((ab & C32(0x80808080)) >> 7) * 27U \
			^ ((ab & C32(0x7F7F7F7F)) << 1); \
		sph_u32 bcx = ((bc & C32(0x80808080)) >> 7) * 27U \
			^ ((bc & C32(0x7F7F7F7F)) << 1); \
		sph_u32 cdx = ((cd & C32(0x80808080)) >> 7) * 27U \
			^ ((cd & C32(0x7F7F7F7F)) << 1); \
		W[ia][n] = abx ^ bc ^ d; \
		W[ib][n] = bcx ^ a ^ cd; \
		W[ic][n] = cdx ^ ab ^ d; \
		W[id][n] = abx ^ bcx ^ cdx ^ ab ^ c; \
	} while (0)

#define MIX_COLUMN(a, b, c, d)   do { \
		MIX_COLUMN1(a, b, c, d, 0); \
		MIX_COLUMN1(a, b, c, d, 1); \
		MIX_COLUMN1(a, b, c, d, 2); \
		MIX_COLUMN1(a, b, c, d, 3); \
	} while (0)

#endif

#define BIG_MIX_COLUMNS   do { \
		MIX_COLUMN(0, 1, 2, 3); \
		MIX_COLUMN(4, 5, 6, 7); \
		MIX_COLUMN(8, 9, 10, 11); \
		MIX_COLUMN(12, 13, 14, 15); \
	} while (0)

#define BIG_ROUND   do { \
		BIG_SUB_WORDS; \
		BIG_SHIFT_ROWS; \
		BIG_MIX_COLUMNS; \
	} while (0)

#define FINAL_SMALL   do { \
		unsigned u; \
		sph_u32 *VV = &sc->u.Vs[0][0]; \
		sph_u32 *WW = &W[0][0]; \
		for (u = 0; u < 16; u ++) { \
			VV[u] ^= sph_dec32le_aligned(sc->buf + (u * 4)) \
				^ sph_dec32le_aligned(sc->buf + (u * 4) + 64) \
				^ sph_dec32le_aligned(sc->buf + (u * 4) + 128) \
				^ WW[u] ^ WW[u + 16] \
				^ WW[u + 32] ^ WW[u + 48]; \
		} \
	} while (0)

#define FINAL_BIG   do { \
		unsigned u; \
		sph_u32 *VV = &sc->u.Vs[0][0]; \
		sph_u32 *WW = &W[0][0]; \
		for (u = 0; u < 32; u ++) { \
			VV[u] ^= sph_dec32le_aligned(sc->buf + (u * 4)) \
				^ WW[u] ^ WW[u + 32]; \
		} \
	} while (0)

#define COMPRESS_SMALL(sc)   do { \
		sph_u32 K0 = sc->C0; \
		sph_u32 K1 = sc->C1; \
		sph_u32 K2 = sc->C2; \
		sph_u32 K3 = sc->C3; \
		unsigned u; \
		INPUT_BLOCK_SMALL(sc); \
		for (u = 0; u < 8; u ++) { \
			BIG_ROUND; \
		} \
		FINAL_SMALL; \
	} while (0)

#define COMPRESS_BIG(sc)   do { \
		sph_u32 K0 = sc->C0; \
		sph_u32 K1 = sc->C1; \
		sph_u32 K2 = sc->C2; \
		sph_u32 K3 = sc->C3; \
		unsigned u; \
		INPUT_BLOCK_BIG(sc); \
		for (u = 0; u < 10; u ++) { \
			BIG_ROUND; \
		} \
		FINAL_BIG; \
	} while (0)

#endif

#define INCR_COUNTER(sc, val)   do { \
		sc->C0 = T32(sc->C0 + (sph_u32)(val)); \
		if (sc->C0 < (sph_u32)(val)) { \
			if ((sc->C1 = T32(sc->C1 + 1)) == 0) \
				if ((sc->C2 = T32(sc->C2 + 1)) == 0) \
					sc->C3 = T32(sc->C3 + 1); \
		} \
	} while (0)

static void
echo_small_init(sph_echo_small_context *sc, unsigned out_len)
{
	sc->u.Vs[0][0] = (sph_u32)out_len;
	sc->u.Vs[0][1] = sc->u.Vs[0][2] = sc->u.Vs[0][3] = 0;
	sc->u.Vs[1][0] = (sph_u32)out_len;
	sc->u.Vs[1][1] = sc->u.Vs[1][2] = sc->u.Vs[1][3] = 0;
	sc->u.Vs[2][0] = (sph_u32)out_len;
	sc->u.Vs[2][1] = sc->u.Vs[2][2] = sc->u.Vs[2][3] = 0;
	sc->u.Vs[3][0] = (sph_u32)out_len;
	sc->u.Vs[3][1] = sc->u.Vs[3][2] = sc->u.Vs[3][3] = 0;
	sc->ptr = 0;
	sc->C0 = sc->C1 = sc->C2 = sc->C3 = 0;
}

static void
echo_big_init(sph_echo_big_context *sc, unsigned out_len)
{
	sc->u.Vs[0][0] = (sph_u32)out_len;
	sc->u.Vs[0][1] = sc->u.Vs[0][2] = sc->u.Vs[0][3] = 0;
	sc->u.Vs[1][0] = (sph_u32)out_len;
	sc->u.Vs[1][1] = sc->u.Vs[1][2] = sc->u.Vs[1][3] = 0;
	sc->u.Vs[2][0] = (sph_u32)out_len;
	sc->u.Vs[2][1] = sc->u.Vs[2][2] = sc->u.Vs[2][3] = 0;
	sc->u.Vs[3][0] = (sph_u32)out_len;
	sc->u.Vs[3][1] = sc->u.Vs[3][2] = sc->u.Vs[3][3] = 0;
	sc->u.Vs[4][0] = (sph_u32)out_len;
	sc->u.Vs[4][1] = sc->u.Vs[4][2] = sc->u.Vs[4][3] = 0;
	sc->u.Vs[5][0] = (sph_u32)out_len;
	sc->u.Vs[5][1] = sc->u.Vs[5][2] = sc->u.Vs[5][3] = 0;
	sc->u.Vs[6][0] = (sph_u32)out_len;
	sc->u.Vs[6][1] = sc->u.Vs[6][2] = sc->u.Vs[6][3] = 0;
	sc->u.Vs[7][0] = (sph_u32)out_len;
	sc->u.Vs[7][1] = sc->u.Vs[7][2] = sc->u.Vs[7][3] = 0;
	sc->ptr = 0;
	sc->C0 = sc->C1 = sc->C2 = sc->C3 = 0;
}

static void
echo_small_compress(sph_echo_small_context *sc)
{
	DECL_STATE_SMALL

	COMPRESS_SMALL(sc);
}

static void
echo_big_compress(sph_echo_big_context *sc)
{
	DECL_STATE_BIG

	COMPRESS_BIG(sc);
}

static void
echo_small_core(sph_echo_small_context *sc,
	const unsigned char *data, size_t len)
{
	unsigned char *buf;
	size_t ptr;

	buf = sc->buf;
	ptr = sc->ptr;
	if (len < (sizeof sc->buf) - ptr) {
		memcpy(buf + ptr, data, len);
		ptr += len;
		sc->ptr = ptr;
		return;
	}

	while (len > 0) {
		size_t clen;

		clen = (sizeof sc->buf) - ptr;
		if (clen > len)
			clen = len;
		memcpy(buf + ptr, data, clen);
		ptr += clen;
		data += clen;
		len -= clen;
		if (ptr == sizeof sc->buf) {
			INCR_COUNTER(sc, 1536);
			echo_small_compress(sc);
			ptr = 0;
		}
	}
	sc->ptr = ptr;
}

static void
echo_big_core(sph_echo_big_context *sc,
	const unsigned char *data, size_t len)
{
	unsigned char *buf;
	size_t ptr;

	buf = sc->buf;
	ptr = sc->ptr;
	if (len < (sizeof sc->buf) - ptr) {
		memcpy(buf + ptr, data, len);
		ptr += len;
		sc->ptr = ptr;
		return;
	}

	while (len > 0) {
		size_t clen;

		clen = (sizeof sc->buf) - ptr;
		if (clen > len)
			clen = len;
		memcpy(buf + ptr, data, clen);
		ptr += clen;
		data += clen;
		len -= clen;
		if (ptr == sizeof sc->buf) {
			INCR_COUNTER(sc, 1024);
			echo_big_compress(sc);
			ptr = 0;
		}
	}
	sc->ptr = ptr;
}

static void
echo_small_close(sph_echo_small_context *sc, unsigned ub, unsigned n,
	void *dst, unsigned out_size_w32)
{
	unsigned char *buf;
	size_t ptr;
	unsigned z;
	unsigned elen;
	union {
		unsigned char tmp[32];
		sph_u32 dummy;
	} u;
	sph_u32 *VV;
	unsigned k;

	buf = sc->buf;
	ptr = sc->ptr;
	elen = ((unsigned)ptr << 3) + n;
	INCR_COUNTER(sc, elen);
	sph_enc32le_aligned(u.tmp, sc->C0);
	sph_enc32le_aligned(u.tmp + 4, sc->C1);
	sph_enc32le_aligned(u.tmp + 8, sc->C2);
	sph_enc32le_aligned(u.tmp + 12, sc->C3);
	/*
	 * If elen is zero, then this block actually contains no message
	 * bit, only the first padding bit.
	 */
	if (elen == 0) {
		sc->C0 = sc->C1 = sc->C2 = sc->C3 = 0;
	}
	z = 0x80 >> n;
	buf[ptr ++] = ((ub & -z) | z) & 0xFF;
	memset(buf + ptr, 0, (sizeof sc->buf) - ptr);
	if (ptr > ((sizeof sc->buf) - 18)) {
		echo_small_compress(sc);
		sc->C0 = sc->C1 = sc->C2 = sc->C3 = 0;
		memset(buf, 0, sizeof sc->buf);
	}
	sph_enc16le(buf + (sizeof sc->buf) - 18, out_size_w32 << 5);
	memcpy(buf + (sizeof sc->buf) - 16, u.tmp, 16);
	echo_small_compress(sc);
	for (VV = &sc->u.Vs[0][0], k = 0; k < out_size_w32; k ++)
		sph_enc32le_aligned(u.tmp + (k << 2), VV[k]);
	memcpy(dst, u.tmp, out_size_w32 << 2);
	echo_small_init(sc, out_size_w32 << 5);
}

static void
echo_big_close(sph_echo_big_context *sc, unsigned ub, unsigned n,
	void *dst, unsigned out_size_w32)
{
	unsigned char *buf;
	size_t ptr;
	unsigned z;
	unsigned elen;
	union {
		unsigned char tmp[64];
		sph_u32 dummy;
	} u;
	sph_u32 *VV;
	unsigned k;

	buf = sc->buf;
	ptr = sc->ptr;
	elen = ((unsigned)ptr << 3) + n;
	INCR_COUNTER(sc, elen);
	sph_enc32le_aligned(u.tmp, sc->C0);
	sph_enc32le_aligned(u.tmp + 4, sc->C1);
	sph_enc32le_aligned(u.tmp + 8, sc->C2);
	sph_enc32le_aligned(u.tmp + 12, sc->C3);
	/*
	 * If elen is zero, then this block actually contains no message
	 * bit, only the first padding bit.
	 */
	if (elen == 0) {
		sc->C0 = sc->C1 = sc->C2 = sc->C3 = 0;
	}
	z = 0x80 >> n;
	buf[ptr ++] = ((ub & -z) | z) & 0xFF;
	memset(buf + ptr, 0, (sizeof sc->buf) - ptr);
	if (ptr > ((sizeof sc->buf) - 18)) {
		echo_big_compress(sc);
		sc->C0 = sc->C1 = sc->C2 = sc->C3 = 0;
		memset(buf, 0, sizeof sc->buf);
	}
	sph_enc16le(buf + (sizeof sc->buf) - 18, out_size_w32 << 5);
	memcpy(buf + (sizeof sc->buf) - 16, u.tmp, 16);
	echo_big_compress(sc);
	for (VV = &sc->u.Vs[0][0], k = 0; k < out_size_w32; k ++)
		sph_enc32le_aligned(u.tmp + (k << 2), VV[k]);
	memcpy(dst, u.tmp, out_size_w32 << 2);
	echo_big_init(sc, out_size_w32 << 5);
}

/* see sph_echo.h */
void
sph_echo224_init(void *cc)
{
	echo_small_init(cc, 224);
}

/* see sph_echo.h */
void
sph_echo224(void *cc, const void *data, size_t len)
{
	echo_small_core(cc, data, len);
}

/* see sph_echo.h */
void
sph_echo224_close(void *cc, void *dst)
{
	echo_small_close(cc, 0, 0, dst, 7);
}

/* see sph_echo.h */
void
sph_echo224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	echo_small_close(cc, ub, n, dst, 7);
}

/* see sph_echo.h */
void
sph_echo256_init(void *cc)
{
	echo_small_init(cc, 256);
}

/* see sph_echo.h */
void
sph_echo256(void *cc, const void *data, size_t len)
{
	echo_small_core(cc, data, len);
}

/* see sph_echo.h */
void
sph_echo256_close(void *cc, void *dst)
{
	echo_small_close(cc, 0, 0, dst, 8);
}

/* see sph_echo.h */
void
sph_echo256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	echo_small_close(cc, ub, n, dst, 8);
}

/* see sph_echo.h */
void
sph_echo384_init(void *cc)
{
	echo_big_init(cc, 384);
}

/* see sph_echo.h */
void
sph_echo384(void *cc, const void *data, size_t len)
{
	echo_big_core(cc, data, len);
}

/* see sph_echo.h */
void
sph_echo384_close(void *cc, void *dst)
{
	echo_big_close(cc, 0, 0, dst, 12);
}

/* see sph_echo.h */
void
sph_echo384_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	echo_big_close(cc, ub, n, dst, 12);
}

/* see sph_echo.h */
void
sph_echo512_init(void *cc)
{
	echo_big_init(cc, 512);
}

/* see sph_echo.h */
void
sph_echo512(void *cc, const void *data, size_t len)
{
	echo_big_core(cc, data, len);
}

/* see sph_echo.h */
void
sph_echo512_close(void *cc, void *dst)
{
	echo_big_close(cc, 0, 0, dst, 16);
}

/* see sph_echo.h */
void
sph_echo512_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	echo_big_close(cc, ub, n, dst, 16);
}
