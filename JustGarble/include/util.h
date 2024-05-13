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


#ifndef UTIL_H_
#define UTIL_H_

#include "aes.h"

int countToN(int *a, int N);
int dbgBlock(__m128i a);
#define RDTSC ({unsigned long long res;  unsigned hi, lo;   __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi)); res =  ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );res;})
int getWords(char *line, char *words[], int maxwords);
#define fbits( v, p) ((v & (1 << p))>>p)
__m128i randomBlock();
void randAESBlock(__m128i* out);
int median(int A[], int n);
double doubleMean(double A[], int n);

// Compute AES in place. out is a __m128i and sched is a pointer to an
// expanded AES key.
#define inPlaceAES(out, sched) {int jx; out = _mm_xor_si128(out, sched[0]);\
                                for (jx = 1; jx < 10; jx++)\
                                  out = _mm_aesenc_si128(out, sched[jx]);\
                                out = _mm_aesenclast_si128(out, sched[jx]);}

extern __m128i __current_rand_index;
extern AES_KEY_JG __rand_aes_key;

#define getRandContext() ((__m128i *) (__rand_aes_key.rd_key));
#define randAESBlock(out,sched) {__current_rand_index++; *out = __current_rand_index;inPlaceAES(*out,sched);}

void JGseedRandomCust(const unsigned char *userKey);
void seedRandom();

#endif /* UTIL_H_ */
