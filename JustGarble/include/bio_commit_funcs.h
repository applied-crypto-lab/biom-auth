
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


#ifndef _OUR_COMMIT_FUNCS_
#define _OUR_COMMIT_FUNCS_

#define AES_NUM_ROUNDS 10
#define AES_BLOCK_SIZE 128

#define SHA2_224 0
#define SHA2_256 1
#define SHA2_384 2
#define SHA2_512 3

#define SHA3_224 10
#define SHA3_256 11
#define SHA3_384 12
#define SHA3_512 13


int AES_expand_key(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int* key, int* expanded_key);

int AESEnc_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs);

int SHA2_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int digest_length, int n, int* inputs, int* outputs);

int SHA3_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int digest_length, int n, int* inputs, int* outputs);



#endif




