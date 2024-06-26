/*
 This file is part of JustGarble.

    JustGarble is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    JustGarble is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with JustGarble.  If not, see <http://www.gnu.org/licenses/>.

*/

/* NOTE This file has been modified from its original form for use in the applied-crypto-lab/biom-auth codebase */


#ifndef common
#define common 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <x86intrin.h>

typedef __m128i block;
#define xorBlocks(x,y) _mm_xor_si128(x,y)
#define zero_block() _mm_setzero_si128()
#define unequal_blocks(x,y) (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) != 0xffff)
#define dbg(X) printf("DEBUG %s:%d says %d \n",__FILE__, __LINE__, X)
#define dbgx(X) printf("DEBUG %s:%d says %X \n",__FILE__, __LINE__, X)
#define dbgp(X) printf("DEBUG %s:%d says %p \n",__FILE__, __LINE__, X)
#define dbgs(X) printf("DEBUG %s:%d says %s \n",__FILE__, __LINE__, X)
#define dbgb(X) printf("DEBUG %s:%d says %lx %lx\n",__FILE__, __LINE__, ((long *)X)[0], ((long *)X)[1])

#define getLSB(x) (*((unsigned short *)&x)&1)
#define makeBlock(X,Y) _mm_set_epi64((__m64)(X), (__m64)(Y))
#define getFromBlock(X,i) _mm_extract_epi64(X, i)

extern int FINAL_ROUND;

/*------------------------------------------------------------------------
/ OCB Version 3 Reference Code (Optimized C)     Last modified 08-SEP-2012
/-------------------------------------------------------------------------
/ Copyright (c) 2012 Ted Krovetz.
/
/ Permission to use, copy, modify, and/or distribute this software for any
/ purpose with or without fee is hereby granted, provided that the above
/ copyright notice and this permission notice appear in all copies.
/
/ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
/ WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
/ MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
/ ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
/ WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
/ ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
/ OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/
/ Phillip Rogaway holds patents relevant to OCB. See the following for
/ his patent grant: http://www.cs.ucdavis.edu/~rogaway/ocb/grant.htm
/
/ Special thanks to Keegan McAllister for suggesting several good improvements
/
/ Comments are welcome: Ted Krovetz <ted@krovetz.net> - Dedicated to Laurel K
/------------------------------------------------------------------------- */
static inline block double_block(block bl) {
		const __m128i mask = _mm_set_epi32(135,1,1,1);
		__m128i tmp = _mm_srai_epi32(bl, 31);
		tmp = _mm_and_si128(tmp, mask);
		tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));
		bl = _mm_slli_epi32(bl, 1);
		return _mm_xor_si128(bl,tmp);
	}
static inline block slow_double_block(block bl) {
                int i;
		__m128i tmp = _mm_srai_epi32(bl, 31);
                for (i=0;i<1;i++){
		const __m128i mask = _mm_set_epi32(135,1,1,1);
		tmp = _mm_and_si128(tmp, mask);
		tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));
		bl = _mm_slli_epi32(bl, 1);
                }
		return _mm_xor_si128(bl,tmp);
	}

static inline block LEFTSHIFT1(block bl) {
		 const __m128i mask = _mm_set_epi32(0,0, (1<<31),0);
		 __m128i tmp = _mm_and_si128(bl,mask);
		bl = _mm_slli_epi64(bl, 1);
		return _mm_xor_si128(bl,tmp);
	}
static inline block RIGHTSHIFT(block bl) {
		 const __m128i mask = _mm_set_epi32(0,1,0,0);
		 __m128i tmp = _mm_and_si128(bl,mask);
		bl = _mm_slli_epi64(bl, 1);
		return _mm_xor_si128(bl,tmp);
	}

#define ADD128(out, in1, in2)                      \
       __asm__("addq %2, %0; adcq %3, %1" :           \
                         "=r"(out.lo64), "=r"(out.hi64) :       \
                         "emr" (in2.lo64), "emr"(in2.hi64),     \
                         "0" (in1.lo64), "1" (in1.hi64));

extern char *__ct;
extern short *__msks;
extern int *__mski;
extern int __itc;
extern char *__itc_src;
extern char *__itc_dst;

inline void TRUNCATE(char *X) {
	char *__ct;
	short *__msks;
	int *__mski;
	{
		__ct = (char*) X;
		__msks = (short*) (&__ct[10]);
		__mski = (int*) (&__ct[10]);
		__mski[0] = 0;
		__msks[2] = 0;
	}
}

inline void TRUNC_COPY(char *X, char *Y) {
	int __itc;
	short*__itc_src;
	short*__itc_dst;
	{
		__itc_src = (short *) X;
		__itc_dst = (short *) Y;
		for (__itc = 0; __itc < 5; __itc++)
			__itc_dst[__itc] = __itc_src[__itc];
	}
}
//#define TRUNCATE(X) {__ct = (char*)X; __msks = (short*)( &__ct[10]);__mski = (int*)( &__ct[10]); __mski[0]=0; __msks[2]=0;}
//#define TRUNC_COPY(X, Y) {__itc_src = (char*)X; __itc_dst = (char*)Y; for(__itc=0;__itc<10;__itc++)__itc_dst[__itc] = __itc_src[__itc];}
#define SUCCESS 0
#define FAILURE -1


#define ROW_REDUCTION
#define FREE_XOR
#define DKC2
//#define TRUNCATED

#define NUM_TESTS 10
#define RUNNING_TIME_ITER 100
block randomBlock();


#endif
