
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


#ifndef _BIO_AUTH_
#define _BIO_AUTH_

#include "../include/justGarble.h"
#include "../include/bio_common.h"
#include "../include/gates.h"
#include "../include/bio_circuits.h"
#include "../include/bio_commit_funcs.h"

#define M_HD_ lg_flr(num_inputs) + lg_flr(input_length)
#define M_ED_ 2*input_length + 1 + lg_flr(num_inputs - 1)
#define M_CS_ 2*input_length + 1 + lg_flr(num_inputs - 1)

#define Q_CUST_ (Q_ED_)
#define Q_CMP_ (Q_HD_)
#define Q_HD_ num_inputs * input_length * lg_flr(num_inputs) * lg_flr(input_length)
#define Q_ED_MULTIPLIER 4
#define Q_ED_ (Q_ED_MULTIPLIER) * q_ed_estimate(num_inputs, input_length)
#define Q_CS_ (Q_ED_)


#define Avail_Mem_ sysconf(_SC_AVPHYS_PAGES) * sysconf(_SC_PAGE_SIZE)


typedef struct
{
	int* feature_vector;
	int* vector_range;
	int* vector_min;
}
BiometricInput;


#define init_GC_bio_auth()\
\
if (Malicious_Security_) {\
	cf_offset += sprintf(circuit_file + cf_offset, "mal_");\
	if (Commit_Func_ == SHA2_256)\
	{\
		cf_offset += sprintf(circuit_file + cf_offset, "sha2-256_");\
		Commit_Digest_Size_ = 256;\
	}\
	if (Commit_Func_ == SHA3_256)\
	{\
		cf_offset += sprintf(circuit_file + cf_offset, "sha3-256_");\
		Commit_Digest_Size_ = 256;\
	}\
}\
sprintf(circuit_file + cf_offset, "%u_%u.scd", num_inputs, input_length);\
if (task == RETURN_FILE_NAME){\
	return;\
}\
\
printf("\nBuilding circuit file %s\n", circuit_file);\
\
int feature_vector_length = num_inputs * input_length;\
int biometric_input_size = feature_vector_length + 64;\
int n = 2 * biometric_input_size;\
\
srand(time(NULL));\
\
GarbledCircuit garbledCircuit;\
GarblingContext garblingContext;\
\
int input_size = n + ((Commit_Digest_Size_ + Commit_Rand_Input_Size_) * Malicious_Security_);\
\
int output_size = Malicious_Security_ ? 3 : 2;\
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
BiometricInput runtime_biom_input;\
BiometricInput enrollment_biom_input; \
\
int runtime_range[SINGLE_LENGTH];\
int runtime_min[SINGLE_LENGTH];\
int enroll_range[SINGLE_LENGTH];\
int enroll_min[SINGLE_LENGTH];\
\
SET_RAW_FLOAT_Circuit(&garbledCircuit, &garblingContext, &init_inputs[feature_vector_length], runtime_range);\
SET_RAW_FLOAT_Circuit(&garbledCircuit, &garblingContext, &init_inputs[feature_vector_length + 32], runtime_min);\
SET_RAW_FLOAT_Circuit(&garbledCircuit, &garblingContext, &init_inputs[biometric_input_size + feature_vector_length], enroll_range);\
SET_RAW_FLOAT_Circuit(&garbledCircuit, &garblingContext, &init_inputs[biometric_input_size + feature_vector_length + 32], enroll_min);\
\
runtime_biom_input.feature_vector = &init_inputs[0];\
runtime_biom_input.vector_range = runtime_range;\
runtime_biom_input.vector_min = runtime_min;\
\
enrollment_biom_input.feature_vector = &init_inputs[biometric_input_size];\
enrollment_biom_input.vector_range = enroll_range;\
enrollment_biom_input.vector_min = enroll_min;\
\
int distance_threshold[SINGLE_LENGTH];\
int dist_func_outputs[SINGLE_LENGTH];\
int final_outputs[output_size];\
\
int threshold_comp_type = LEQ;



#define finalize_GC_bio_auth()\
\
int cmp_outputs[2];\
FLOAT_CMP_Circuit_2I(&garbledCircuit, &garblingContext, threshold_comp_type, INFTY_EQ_NAN, distance_threshold, dist_func_outputs, cmp_outputs);\
memcpy(final_outputs, cmp_outputs, sizeof(int));\
\
finishBuilding(&garbledCircuit, &garblingContext, out_labels, final_outputs);\
writeCircuitToFile(&garbledCircuit, circuit_file);\
\
free(in_labels);\
free(out_labels);



#define verify_commitment()\
\
int verif_input_size = biometric_input_size + Commit_Rand_Input_Size_;\
int verification_inputs[verif_input_size];\
int verification_outputs[Commit_Digest_Size_];\
\
memcpy(verification_inputs,  enrollment_biom_input.feature_vector, biometric_input_size * sizeof(int));\
memcpy(&verification_inputs[biometric_input_size],  &init_inputs[input_size  - Commit_Digest_Size_ - Commit_Rand_Input_Size_], Commit_Rand_Input_Size_ * sizeof(int));\
\
if (Commit_Func_ == SHA2_256)\
{\
	SHA2_Circuit(&garbledCircuit, &garblingContext, 256, verif_input_size, verification_inputs, verification_outputs);\
}\
else if (Commit_Func_ == SHA3_256)\
{\
	SHA3_Circuit(&garbledCircuit, &garblingContext, 256, verif_input_size, verification_inputs, verification_outputs);\
}\
\
CMP_Circuit_2I(&garbledCircuit, &garblingContext, 2 * Commit_Digest_Size_, EQ, verification_outputs, &init_inputs[input_size - Commit_Digest_Size_], &final_outputs[2]);\




extern int Malicious_Security_;
extern int Commit_Digest_Size_;
extern int Commit_Rand_Input_Size_;
extern int Commit_Func_;


long q_ed_estimate(int num_inputs, int input_length);

void build_hamming(int num_inputs, int input_length, char *circuit_file, int task);
void build_euclidean(int num_inputs, int input_length, char *circuit_file, int task);
void build_cosine(int num_inputs, int input_length, char *circuit_file, int task);


#endif

