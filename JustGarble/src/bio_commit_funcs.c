
/*
	Privacy Preserving Biometric Authentication for Fingerprints and Beyond
	Copyright (C) 2024  Marina Blanton and Dennis Murphy,
	University at Buffalo, State University of New York.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../include/util.h"
#include "../include/justGarble.h"
#include "../include/circuits.h"
#include "../include/gates.h"
#include "../include/bio_common.h"
#include "../include/bio_commit_funcs.h"
#include "../include/bio_circuits.h"



/////////////////	AES Functions


//TODO make sure AESCircuits has been updated with this and other *_Circuit2() functions


int AES_expand_key(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int* key, int* expanded_key) {

	int in_sw[32];
	int in_xor_1[32];
	int in_xor_2[64];
	int temp[32];
	int offset = 128;

	memcpy(expanded_key, key, 128 * sizeof(int));

	for (int round = 0; round < AES_NUM_ROUNDS; round++) {

		memcpy(temp, &expanded_key[offset - 32], 32 * sizeof(int));
		memcpy(in_xor_1, &expanded_key[offset - 128], 32 * sizeof(int));

		//RotWord()
		SHIFT_Circuit(garbledCircuit, garblingContext, 32, 8, LEFT, CIRCULAR, POSITIVE, temp, in_sw);

		//SubWord()
		//TODO integrate NewSBOXCircuit into const-op paradigm
		NewSBOXCircuit(garbledCircuit, garblingContext, in_sw, in_xor_1);
		NewSBOXCircuit(garbledCircuit, garblingContext, &in_sw[8], &in_xor_1[8]);
		NewSBOXCircuit(garbledCircuit, garblingContext, &in_sw[16], &in_xor_1[16]);
		NewSBOXCircuit(garbledCircuit, garblingContext, &in_sw[24], &in_xor_1[24]);


		//XOR with Rcon[i/Nk] indices in words; NIST FIPS 197 Figure 11
		//See Table A.1 for further details
		if (round < 8) {
			NOT_Gate2(garbledCircuit, garblingContext, in_xor_1[24 + round], &in_xor_1[24 + round]);
		}
		else {
			NOT_Gate2(garbledCircuit, garblingContext, in_xor_1[16 + round], &in_xor_1[16 + round]);
			NOT_Gate2(garbledCircuit, garblingContext, in_xor_1[17 + round], &in_xor_1[17 + round]);
			NOT_Gate2(garbledCircuit, garblingContext, in_xor_1[19 + round], &in_xor_1[19 + round]);
			NOT_Gate2(garbledCircuit, garblingContext, in_xor_1[20 + round], &in_xor_1[20 + round]);
		}

		memcpy(in_xor_2, in_xor_1, 32 * sizeof(int));
		memcpy(&in_xor_2[32], temp, 32 * sizeof(int));

		//W[i] = temp XOR w[i-Nk] indices in words; NIST FIPS 197 Figure 11, Table A.1
		for (int i = 0; i < 4; i++) {
			MIXED_OP_Circuit(garbledCircuit, garblingContext, 64, XOR, in_xor_2, &expanded_key[offset + i*32]);
			//w[i-1], W[i-Nk] indices in words; NIST FIPS 197 Figure 11
			memcpy(in_xor_2, &expanded_key[offset - 32], 32 * sizeof(int));
			memcpy(&in_xor_2[32], &expanded_key[offset - 128], 32 * sizeof(int));
		}

		offset += 128;
	}
	return 0;
}


//TODO integrate AddRoundKey, SubBytes, ShiftRows, MixColumns into const-op paradigm
int AESEnc_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs) {

	int expanded_key[128 * (AES_NUM_ROUNDS + 1)];
	int in_add_key[256];
	int out_add_key[128];
	int out_sub_bytes[128];
	int out_shift_row[128];

	AES_expand_key(garbledCircuit, garblingContext, inputs, expanded_key);

	int num_blocks =  n / 128;
	int last_block_size = n % 128 == 0 ? 128 : n % 128;
	for (int block = 0; block < num_blocks; block++) {

		if (block == num_blocks - 1)
		{
			memcpy(in_add_key, &inputs[128 * block], last_block_size * sizeof(block));
			for (int i = last_block_size; i < 128; i++)
				in_add_key[i] = fixedZeroWire(garbledCircuit, garblingContext);
		}
		else
			memcpy(in_add_key, &inputs[128 * block], 128 * sizeof(block));

		memcpy(&in_add_key[128], expanded_key, 128 * sizeof(block));
		AddRoundKey(garbledCircuit, garblingContext, in_add_key, out_add_key);

		for (int round = 0; round < AES_NUM_ROUNDS; round++) {

			for (int i = 0; i < 16; i++) {
				SubBytes(garbledCircuit, garblingContext, &out_add_key[8*i], &out_sub_bytes[8*i]);
			}

			ShiftRows(garbledCircuit, garblingContext, out_sub_bytes, out_shift_row);

			for (int i = 0; i < 4; i++) {
				if (round != AES_NUM_ROUNDS - 1)
					MixColumns(garbledCircuit, garblingContext, &out_shift_row[i*32], &in_add_key[i*32]);
				else
					memcpy(&in_add_key[i*32], &out_shift_row[i*32], 32 * sizeof(int));
			}

			memcpy(&in_add_key[128], &expanded_key[128*(round+1)], 128 * sizeof(int));

			AddRoundKey(garbledCircuit, garblingContext, in_add_key, out_add_key);
		}
	}

	memcpy(outputs, out_add_key, AES_BLOCK_SIZE * sizeof(int));
}





/////////////////	SHA Functions



//////	SHA 2 Functions

int SHA_SHR_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int w, int *inputs, int *outputs)
{
	//CAUTION w is used here where n is normally used within JG, and n instead refers to shift value within ROTR or SHR
	//CAUTION this is to maintain compatibility with NIST 180.4 notation. For SHA256, input size w = 32 (bit word)
	memcpy(outputs, &inputs[n], (w - n) * sizeof(int));
	for (int i = w - n; i < w; i++)
		outputs[i] = fixedZeroWire(garbledCircuit, garblingContext);
}



int SHA_ROTR_Circuit(int n, int w, int *inputs, int *outputs)
{
	//CAUTION w is used here where n is normally used within JG, and n instead refers to shift value within ROTR or SHR
	//CAUTION this is to maintain compatibility with NIST 180.4 notation. For SHA256, input size w = 32 (bit word)
	memcpy(outputs, &inputs[n], (w - n) * sizeof(int));
	memcpy(&outputs[w - n], inputs, n * sizeof(int));
}



int SHA_SIGMA_0_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int d, int *inputs, int *outputs)
{
	//CAUTION w is used here where n is normally used within JG, and n instead refers to shift value within ROTR or SHR
	//CAUTION this is to maintain compatibility with NIST 180.4 notation. For SHA256, input size w = 32 (bit word)
	int w = d / 8;
	int in_xor_1[2 * w];
	int in_xor_2[2 * w];

	if (d == 256)
	{
		SHA_ROTR_Circuit(2, w, inputs, in_xor_1);
		SHA_ROTR_Circuit(13, w, inputs, &in_xor_1[w]);
		SHA_ROTR_Circuit(22, w, inputs, in_xor_2);
	}
	else
	{
		SHA_ROTR_Circuit(28, w, inputs, in_xor_1);
		SHA_ROTR_Circuit(34, w, inputs, &in_xor_1[w]);
		SHA_ROTR_Circuit(39, w, inputs, in_xor_2);
	}

	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, XOR, in_xor_1, &in_xor_2[w]);
	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, XOR, in_xor_2, outputs);
}



int SHA_SIGMA_1_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int d, int *inputs, int *outputs)
{
	//CAUTION w is used here where n is normally used within JG, and n instead refers to shift value within ROTR or SHR
	//CAUTION this is to maintain compatibility with NIST 180.4 notation. For SHA256, input size w = 32 (bit word)
	int w = d / 8;
	int in_xor_1[2 * w];
	int in_xor_2[2 * w];

	if (d == 256)
	{
		SHA_ROTR_Circuit(6, w, inputs, in_xor_1);
		SHA_ROTR_Circuit(11, w, inputs, &in_xor_1[w]);
		SHA_ROTR_Circuit(25, w, inputs, in_xor_2);
	}
	else
	{
		SHA_ROTR_Circuit(14, w, inputs, in_xor_1);
		SHA_ROTR_Circuit(18, w, inputs, &in_xor_1[w]);
		SHA_ROTR_Circuit(41, w, inputs, in_xor_2);
	}

	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, XOR, in_xor_1, &in_xor_2[w]);
	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, XOR, in_xor_2, outputs);
}



int SHA_sigma_0_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int d, int *inputs, int *outputs)
{
	//CAUTION w is used here where n is normally used within JG, and n instead refers to shift value within ROTR or SHR
	//CAUTION this is to maintain compatibility with NIST 180.4 notation. For SHA256, input size w = 32 (bit word)
	int w = d / 8;
	int in_xor_1[2 * w];
	int in_xor_2[2 * w];

	if (d == 256)
	{
		SHA_ROTR_Circuit(7, w, inputs, in_xor_1);
		SHA_ROTR_Circuit(18, w, inputs, &in_xor_1[w]);
		SHA_SHR_Circuit(garbledCircuit, garblingContext, 3, w, inputs, in_xor_2);
	}
	else
	{
		SHA_ROTR_Circuit(1, w, inputs, in_xor_1);
		SHA_ROTR_Circuit(8, w, inputs, &in_xor_1[w]);
		SHA_SHR_Circuit(garbledCircuit, garblingContext, 7, w, inputs, in_xor_2);
	}

	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, XOR, in_xor_1, &in_xor_2[w]);
	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, XOR, in_xor_2, outputs);
}



int SHA_sigma_1_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int d, int *inputs, int *outputs)
{
	//CAUTION w is used here where n is normally used within JG, and n instead refers to shift value within ROTR or SHR
	//CAUTION this is to maintain compatibility with NIST 180.4 notation. For SHA256, input size w = 32 (bit word)
	int w = d / 8;
	int in_xor_1[2 * w];
	int in_xor_2[2 * w];

	if (d == 256)
	{
		SHA_ROTR_Circuit(17, w, inputs, in_xor_1);
		SHA_ROTR_Circuit(19, w, inputs, &in_xor_1[w]);
		SHA_SHR_Circuit(garbledCircuit, garblingContext, 10, w, inputs, in_xor_2);
	}
	else
	{
		SHA_ROTR_Circuit(19, w, inputs, in_xor_1);
		SHA_ROTR_Circuit(61, w, inputs, &in_xor_1[w]);
		SHA_SHR_Circuit(garbledCircuit, garblingContext, 6, w, inputs, in_xor_2);
	}

	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, XOR, in_xor_1, &in_xor_2[w]);
	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, XOR, in_xor_2, outputs);
}



int SHA_CH_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int d, int *inx, int *iny, int *inz, int *outputs)
{
	//CAUTION w is used here where n is normally used within JG, and n instead refers to shift value within ROTR or SHR
	//CAUTION this is to maintain compatibility with NIST 180.4 notation. For SHA256, input size w = 32 (bit word)
	int w = d / 8;
	int notx[w];
	memcpy(notx, inx, w * sizeof(int));
	NOT_Circuit2(garbledCircuit, garblingContext, w, inx, notx);

	int in_and[2 * w];
	int in_xor[2 * w];

	memcpy(in_and, inx, w * sizeof(int));
	memcpy(&in_and[w], iny, w * sizeof(int));
	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, AND, in_and, in_xor);

	memcpy(in_and, notx, w * sizeof(int));
	memcpy(&in_and[w], inz, w * sizeof(int));
	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, AND, in_and, &in_xor[w]);

	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, XOR, in_xor, outputs);
}



int SHA_MAJ_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int d, int *inx, int *iny, int *inz, int *outputs)
{
	//CAUTION w is used here where n is normally used within JG, and n instead refers to shift value within ROTR or SHR
	//CAUTION this is to maintain compatibility with NIST 180.4 notation. For SHA256, input size w = 32 (bit word)
	int w = d / 8;
	int in_and[2 * w];
	int in_xor_1[2 * w];
	int in_xor_2[2 * w];

	memcpy(in_and, inx, w * sizeof(int));
	memcpy(&in_and[w], iny, w * sizeof(int));

	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, AND, in_and, in_xor_1);

	memcpy(&in_and[w], inz, w * sizeof(int));
	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, AND, in_and, &in_xor_1[w]);

	memcpy(in_and, iny, w * sizeof(int));
	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, AND, in_and, in_xor_2);

	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, XOR, in_xor_1, &in_xor_2[w]);
	MIXED_OP_Circuit(garbledCircuit, garblingContext, 2 * w, XOR, in_xor_2, outputs);
}



//CAUTION the code below only supports digest_length in {256, 512}
//NOTE digest_length in {224, 384} are slight modifications to {256, 512} respectively
//NOTE these are of the same runtime complexity despite weaker security
//NOTE to allow these disget lengths, set word_length and nrep_size to 256, 512 values
//NOTE and set init constants K_* and init_H_val_* for * in {224, 384} from NIST specs
//NOTE the calls to the subfuntionalities will also need to use d in {256, 512}

int SHA2_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int digest_length, int n, int* inputs, int* outputs)
{
	int word_length = digest_length / 8;
	int nrep_size = digest_length / 4;

	//padding
	int k = (digest_length * 448 / 256) - 1 - n;
	while (k < 0) k += (2 * digest_length);

	int padded_input[n + k + nrep_size + 1];
	memcpy(padded_input, inputs, n * sizeof(int));
	padded_input[n] = fixedOneWire(garbledCircuit, garblingContext);
	for (int u = n + 1; u < n + k + 1; u++)
		padded_input[u] = fixedZeroWire(garbledCircuit, garblingContext);

	int mask = 1 << (8 * sizeof(int) - 1);
	for (int u = 0; u < 8 * sizeof(int); u++)
	{
		if (n & mask)
			padded_input[n + k + u + nrep_size + 1 - (8 * sizeof(int))] = fixedOneWire(garbledCircuit, garblingContext);
		else
			padded_input[n + k + u + nrep_size + 1 - (8 * sizeof(int))] = fixedZeroWire(garbledCircuit, garblingContext);
		mask >>= 1;
	}

	//NOTE the following loop prepends zeros in the bit representation of n, which appears in the preceding loop
	for (int u = 8 * sizeof(int); u < nrep_size; u++)
	{
		padded_input[n + k + u + 1 - (8 * sizeof(int))] = fixedZeroWire(garbledCircuit, garblingContext);
	}

	int K_256[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	int K_512[160] = {
		0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
		0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
		0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
		0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
		0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
		0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
		0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
		0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
		0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
		0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
		0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
		0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
		0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
		0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
		0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
		0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
		0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
		0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
		0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
		0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
	};

	int H[8][word_length];

	int init_H_val_256[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};
	int init_H_val_512[16] = {
		0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
		0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179
	};

	if (digest_length == 256)
		SETCONST_Circuit(garbledCircuit, garblingContext, 8 * sizeof(init_H_val_256), init_H_val_256, (int*) H);
	else
		SETCONST_Circuit(garbledCircuit, garblingContext, 8 * sizeof(init_H_val_512), init_H_val_512, (int*) H);


	int num_blocks = (n + k + nrep_size + 1) / (2 * digest_length);

	//printf("%i\t%i\t%i\n", n, k, num_blocks);

	for (int i = 0; i < num_blocks; i++)
	{

		int W[64][word_length];
		int in_add_1[2 * word_length];
		int in_add_2[2 * word_length];
		int in_add_3[2 * word_length];

		for (int t = 0; t < 16; t++)
			memcpy((int*) &W[t], &padded_input[(2*i * digest_length) + (t * word_length)], word_length * sizeof(int));

		for (int u = 1; u < 4; u++)
		{
			for (int t = 0; t < 16; t++)
			{
				int in_sig_0[word_length];
				int in_sig_1[word_length];

				memcpy(in_add_1, (int*) &W[(u * 16) + t - 7], word_length * sizeof(int));
				memcpy(&in_add_1[word_length], (int*) &W[(u * 16) + t - 16], word_length * sizeof(int));
				ADD_Circuit2(garbledCircuit, garblingContext, 2 * word_length, NO_OVERFLOW, in_add_1, in_add_3);

				memcpy(in_sig_0, (int*) &W[(u * 16) + t - 15], word_length * sizeof(int));
				SHA_sigma_0_Circuit(garbledCircuit, garblingContext, digest_length, in_sig_0, in_add_2);

				memcpy(in_sig_1, (int*) &W[(u * 16) + t - 2], word_length * sizeof(int));
				SHA_sigma_1_Circuit(garbledCircuit, garblingContext, digest_length, in_sig_1, &in_add_2[word_length]);

				ADD_Circuit2(garbledCircuit, garblingContext, 2 * word_length, NO_OVERFLOW, in_add_2, &in_add_3[word_length]);
				ADD_Circuit2(garbledCircuit, garblingContext, 2 * word_length, NO_OVERFLOW, in_add_3, (int*) &W[(u * 16) + t]);
			}
		}

		//initialize a..h as V
		int V[8][word_length];
		memcpy(V, H, 8 * word_length * sizeof(int));

		for(int t = 0; t  < 64; t++)
		{
			int T1[word_length];
			int T2[word_length];

			SHA_SIGMA_0_Circuit(garbledCircuit, garblingContext, digest_length, (int*) &V[0], in_add_1);
			SHA_MAJ_Circuit(garbledCircuit, garblingContext, digest_length, (int*) &V[0], (int*) &V[1], (int*) &V[2], &in_add_1[word_length]);

			ADD_Circuit2(garbledCircuit, garblingContext, 2 * word_length, NO_OVERFLOW, in_add_1, T2);

			SHA_SIGMA_1_Circuit(garbledCircuit, garblingContext, digest_length, (int*) &V[4], in_add_1);
			SHA_CH_Circuit(garbledCircuit, garblingContext, digest_length, (int*) &V[4], (int*) &V[5], (int*) &V[6], &in_add_1[word_length]);

			ADD_Circuit2(garbledCircuit, garblingContext, 2 * word_length, NO_OVERFLOW, in_add_1, in_add_2);

			memcpy(&in_add_2[word_length], (int*) &V[7], word_length * sizeof(int));
			ADD_Circuit2(garbledCircuit, garblingContext, 2 * word_length, NO_OVERFLOW, in_add_2, in_add_1);

			memcpy(&in_add_1[word_length], (int*) &W[t], word_length * sizeof(int));
			ADD_Circuit2(garbledCircuit, garblingContext, 2 * word_length, NO_OVERFLOW, in_add_1, in_add_2);;

			if (digest_length == 256)
				SETCONST_Circuit(garbledCircuit, garblingContext, word_length, &K_256[t], &in_add_2[word_length]);
			else
				SETCONST_Circuit(garbledCircuit, garblingContext, word_length, &K_512[2*t], &in_add_2[word_length]);

			ADD_Circuit2(garbledCircuit, garblingContext, 2 * word_length, NO_OVERFLOW, in_add_2, T1);

			memcpy((int*) &V[7], (int*) &V[6], word_length * sizeof(int));
			memcpy((int*) &V[6], (int*) &V[5], word_length * sizeof(int));
			memcpy((int*) &V[5], (int*) &V[4], word_length * sizeof(int));
			memcpy(in_add_1, (int*) &V[3], word_length * sizeof(int));
			memcpy(&in_add_1[word_length], T1, word_length * sizeof(int));

			ADD_Circuit2(garbledCircuit, garblingContext, 2 * word_length, NO_OVERFLOW, in_add_1, (int*) &V[4]);

			memcpy((int*) &V[3], (int*) &V[2], word_length * sizeof(int));
			memcpy((int*) &V[2], (int*) &V[1], word_length * sizeof(int));
			memcpy((int*) &V[1], (int*) &V[0], word_length * sizeof(int));
			memcpy(in_add_1, T1, word_length * sizeof(int));
			memcpy(&in_add_1[word_length], T2, word_length * sizeof(int));

			ADD_Circuit2(garbledCircuit, garblingContext, 2 * word_length, NO_OVERFLOW, in_add_1, (int*) &V[0]);
		}

		int in_add_H[2 * word_length];
		for (int u = 0; u < 8; u++)
		{
			memcpy(in_add_H, (int*) &H[u], word_length * sizeof(int));
			memcpy(&in_add_H[word_length], (int*) &V[u], word_length * sizeof(int));

			ADD_Circuit2(garbledCircuit, garblingContext, 2 * word_length, NO_OVERFLOW, in_add_H, (int*) &H[u]);
		}
	}

	for (int u = 0; u < 8; u++)
		memcpy(&outputs[u * word_length], (int*) &H[u], word_length * sizeof(int));
}






//////	SHA 3 Functions


int SHA_THETA_CIRCUIT(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int (*A)[5][64])
{
	int C[5][64];
	int D[5][64];

	for (int x = 0; x < 5; x++){
		for (int z = 0; z < 64; z++){
			C[x][z] = A[x][0][z];
		}
	}

	for (int y = 1; y < 5; y++){
		for (int x = 0; x < 5; x++){
			for (int z = 0; z < 64; z++){
				MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, C[x][z], A[x][y][z], &C[x][z]);
			}
		}
	}

	for (int x = 0; x < 5; x++){
		for (int z = 0; z < 64; z++){
			MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, C[(x+4) % 5][z], C[(x+1) % 5][(z + 63) % 64], &D[x][z]);
		}
	}

	for (int y = 0; y < 5; y++){
		for (int x = 0; x < 5; x++){
			for (int z = 0; z < 64; z++){
				MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, A[x][y][z], D[x][z], &A[x][y][z]);
			}
		}
	}
}



int SHA_RHO_CIRCUIT(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int (*A)[5][64])
{
	int B[5][5][64];

	memcpy(B, A, 1600 * sizeof(int));

	int x = 1;
	int y = 0;
	for (int t = 0; t < 24; t++)
	{
		for (int z = 0; z < 64; z++)
		{
			int omega = (z - (t+1)*(t+2)/2) % 64;
			while (omega < 0) omega += 64;
			B[x][y][z] = A[x][y][omega];
			x = y;
			y = (2*x + 3*y) % 5;
		}
	}
	memcpy(A, B, 1600 * sizeof(int));
}



int SHA_PI_CIRCUIT(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int (*A)[5][64])
{
	int B[5][5][64];

	memcpy(B, A, 1600 * sizeof(int));

	for (int y = 0; y < 5; y++){
		for (int x = 0; x < 5; x++){
			for (int z = 0; z < 64; z++){
				int alpha = (x + 3*y) % 5;
				B[x][y][z] = A[alpha][x][z];
			}
		}
	}
	memcpy(A, B, 1600 * sizeof(int));
}



int SHA_CHI_CIRCUIT(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int (*A)[5][64])
{
	for (int y = 0; y < 5; y++){
		for (int x = 0; x < 5; x++){
			for (int z = 0; z < 64; z++){
				int a = A[(x+1) % 5][y][z];
				int b;
				int c;
				NOT_Gate2(garbledCircuit, garblingContext, A[(x+2) % 5][y][z], &b);
				MIXED_OP_Gate(garbledCircuit, garblingContext, AND, a, b, &c);
				MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, A[x][y][z], c, &A[x][y][z]);
			}
		}
	}
}


//set bit i in r to be b
int set_bit(int r, int b, int i, int mod_bits)
{
	r &= (((1 << (1 + mod_bits)) -1) ^ (1 << i));
	return r | (b << i);
}


#define r_bit(i) ((r & (1 << i)) >> i) ^ ((r & 256) >> 8)

int SHA_RC(int t)
{
	if (t % 255 == 0)
		return 1;
	int r = 128;
	for (int i = 0; i < t % 255; i++)
	{
		r = set_bit(r, 0, 9, 9);
		r = set_bit(r, r_bit(0), 0, 9);
		r = set_bit(r, r_bit(4), 4, 9);
		r = set_bit(r, r_bit(5), 5, 9);
		r = set_bit(r, r_bit(6), 6, 9);
	}
	return r & 1;
}



int SHA_IOTA_CIRCUIT(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int pass_num, int (*A)[5][64])
{
	int RC[64];

	int k = 0;
	for (int j = 0; j < 7; j++)
	{
		if (j > 1) {
			for (int i = 0; i < (1 << (j-1)) - 1; i++) {
				RC[k++] = fixedZeroWire(garbledCircuit, garblingContext);
			}
		}
		if (SHA_RC(j + 7*pass_num))
			RC[k++] = fixedOneWire(garbledCircuit, garblingContext);
		else
			RC[k++] = fixedZeroWire(garbledCircuit, garblingContext);
	}

	for (int z = 0; z < 64; z++)
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, A[0][0][z], RC[z], &A[0][0][z]);
}



int SHA3_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int digest_length, int n, int* inputs, int* outputs)
{
	int b = 1600;				// "width"
	int c = 2 * digest_length;	// "capacity"
	int r = b - c;				// "rate"

	int S[3200];
	int A[5][5][64];

	int num_rounds = 1 + ((n-1) / r);
	int num_pad_zeros = (-n-2) % r;
	while (num_pad_zeros < 0) num_pad_zeros += r;
	int last_pad_one_offset = 3 + num_pad_zeros;

	for (int i = 0; i < 1600; i++)
		S[i] = fixedZeroWire(garbledCircuit, garblingContext);

	for (int round_num = 0; round_num < num_rounds; round_num++)
	{
		int input_bytes = round_num < num_rounds-1 ? r : n % r;
		memcpy(&S[1600], &inputs[r * round_num], input_bytes * sizeof(int));

		for (int i = 0; i < b - input_bytes; i++)
		{
			if ((round_num == num_rounds-1) && ((i == 1) || (i == 2) || (i == last_pad_one_offset)))
				S[1600 + input_bytes + i] = fixedOneWire(garbledCircuit, garblingContext);
			else
				S[1600 + input_bytes + i] = fixedZeroWire(garbledCircuit, garblingContext);
		}

		MIXED_OP_Circuit(garbledCircuit, garblingContext, 3200, XOR, S, S);

		for (int y = 0; y < 5; y++){
			for (int x = 0; x < 5; x++){
				for (int z = 0; z < 64; z++){
					//CAUTION see note on similar loop below
					A[x][y][z] = S[320*y + 64*x + z];
				}
			}
		}

		for (int pass_num = 0; pass_num < 24; pass_num++)
		{
			SHA_THETA_CIRCUIT(garbledCircuit, garblingContext, A);
			SHA_RHO_CIRCUIT(garbledCircuit, garblingContext, A);
			SHA_PI_CIRCUIT(garbledCircuit, garblingContext, A);
			SHA_CHI_CIRCUIT(garbledCircuit, garblingContext, A);
			SHA_IOTA_CIRCUIT(garbledCircuit, garblingContext, pass_num, A);
		}
	}

	int *T = outputs;
	for (int y = 0; y < 5; y++){
		for (int x = 0; x < 5; x++){
			for (int z = 0; z < 64; z++){
				//CAUTION assignment in line below is equivalent to linear combination above iff the for loops are nested in order {y, x, z}
				*(T++) = A[x][y][z];
				if (T - outputs == digest_length) break;
			}
		}
	}
}









