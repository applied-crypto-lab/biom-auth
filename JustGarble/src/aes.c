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


#include "../include/aes.h"

extern void AES_128_Key_Expansion(const unsigned char *userkey, void *key);
extern void AES_192_Key_Expansion(const unsigned char *userkey, void *key);
extern void AES_256_Key_Expansion(const unsigned char *userkey, void *key);

extern int AES_set_encrypt_key_JG(const unsigned char *userKey, const int bits, AES_KEY_JG *key);
extern void AES_set_decrypt_key_fast(AES_KEY_JG *dkey, const AES_KEY_JG *ekey);
extern int AES_set_decrypt_key_JG(const unsigned char *userKey, const int bits, AES_KEY_JG *key);

extern void AES_encrypt_JG(const unsigned char *in, unsigned char *out, const AES_KEY_JG *key);
extern void AES_decrypt_JG(const unsigned char *in, unsigned char *out, const AES_KEY_JG *key);
extern void AES_ecb_encrypt_blks(block *blks, unsigned nblks, AES_KEY_JG *key);
extern void AES_ecb_encrypt_blks_4(block *blks, AES_KEY_JG *key);
extern void AES_ecb_decrypt_blks(block *blks, unsigned nblks, AES_KEY_JG *key);

