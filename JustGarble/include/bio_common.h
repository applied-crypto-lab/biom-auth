
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


#ifndef _OUR_COMMON_H_
#define _OUR_COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <ctype.h>
#include "../include/justGarble.h"
#include "../include/circuit_test_and_gen.h"


#define FNAME_LEN_ 255
#define MAX_FILES_ 256

#define SIGNED 1
#define UNSIGNED 0

#define ENTRANCE 0
#define EXIT 1

#define POSITIVE 1
#define NEGATIVE 0

#define LEFT 0
#define RIGHT 1

#define ADD 0
#define REMOVE 1

#define TRUNC 0
#define CIRCULAR 1

#define BUILD_CIRCUIT 0
#define RETURN_FILE_NAME 1

#define AND 0
#define OR 1
#define XOR 2


#define M_FULL_ 2 * num_inputs * input_length
#define M_MULT_ (M_FULL_)
#define M_CUST_ (M_ED_)
#define M_CMP_ 1
#define M_XOR_ num_inputs * input_length
#define M_ADD_ num_inputs * input_length


#define Q_FULL_ (M_FULL_)
#define Q_KAR_ input_length * input_length * lg_flr(input_length) * lg_flr(input_length)
#define Q_XOR_ 2 * num_inputs * input_length
#define Q_ADD_ 12 * num_inputs * input_length
#define Q_MULT_ 12 * num_inputs * num_inputs * input_length * input_length
#define Q_FLOAT_ 262144


#define CIRCUIT_DIR_ "./circuit_files/"


#define init_GC()\
\
sprintf(circuit_file + cf_offset, "%u_%u.scd", num_inputs, input_length);\
if (task == RETURN_FILE_NAME){\
	return;\
}\
\
printf("\nBuilding circuit file %s\n", circuit_file);\
\
int split = num_inputs * input_length;\
int n = 2 * split;\
\
srand(time(NULL));\
\
GarbledCircuit garbledCircuit;\
GarblingContext garblingContext;\
\
int input_size = n;\
int output_size = m;\
\
block *in_labels = (block*) malloc(2 * input_size * sizeof(block));\
block *out_labels = (block*) malloc(2 * output_size * sizeof(block));\
\
createInputLabels(in_labels, input_size);\
createEmptyGarbledCircuit(&garbledCircuit, input_size, output_size, q, r, in_labels);\
startBuilding(&garbledCircuit, &garblingContext);\
\
int init_inputs[input_size];\
countToN(init_inputs, input_size);\
\
int final_outputs[output_size];



#define finalize_GC()\
\
finishBuilding(&garbledCircuit, &garblingContext, out_labels, final_outputs);\
writeCircuitToFile(&garbledCircuit, circuit_file);\
\
free(in_labels);\
free(out_labels);



int lg_flr(int x);
int strtouint(char *str, int *result);
void int_to_bit_vector(int x, int *v, int input_length);
int bit_vector_to_int(int *v, int input_length);
void intarr_to_bit_vector(int *x, int *v, int input_length);
void bit_vector_to_intarr(int *x, int *v, int input_length);
void print_bit_vector(int *v, int input_length);
int count_set_bits(int x);
void twos_complement(int *in, int *out, int input_length);
void bit_vector_add(int *ina, int *inb, int *out, int input_length);
void bit_vector_add(int *ina, int *inb, int *out, int input_length);
void bit_vector_add_ovflw(int *ina, int *inb, int *out, int input_length);
void bit_vector_bin_add(int *ina, int *inb, int *out, int input_length);
void bit_vector_bin_add_ovflw(int *ina, int *inb, int *out, int input_length);
void bit_vector_mul(int *ina, int *inb, int *out, int input_length);
void bit_vector_bitmul(int ina, int *inb, int *out, int input_length);
int bit_vector_les(int *ina, int *inb, int input_length);
void bit_vector_not(int *in, int *out, int input_length);
void bit_vector_min(int *ina, int *inb, int *out, int input_length);
void bit_vector_max(int *ina, int *inb, int *out, int input_length);
int bit_vector_msb(int *inputs, int input_length);
int int_msb(int x);


#endif


