
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


#include <unistd.h>
#include <time.h>
#include "../include/justGarble.h"
#include "../include/bio_auth.h"
#include "../include/bio_common.h"


int Malicious_Security_ = 0;
int Commit_Digest_Size_ = 0;
int Commit_Func_ = SHA2_256;
int Commit_Rand_Input_Size_ = 128;


long q_ed_estimate(int num_inputs, int input_length) {

	int n = 1;
	int l = 1;
	long delta = 63;
	long epsilon = 5;
	long estimate = 39;

	while (l < input_length) {
		estimate = (4 * estimate) - delta;
		delta = (2 * delta) + epsilon;
		epsilon = (2 * epsilon) + 9;
		l *= 2;
	}

	while (n < num_inputs) {
		estimate = (2 * estimate) + (10 * n);
		n *= 2;
	}

	long mem_ceiling = 7 * Avail_Mem_ / (8 * Q_ED_MULTIPLIER);

	return estimate < mem_ceiling ? estimate : mem_ceiling;
}




/////////	Distance Metric Functions for Biometric Authentication



//uses recursive addition approach to counting bits once initial XOR is taken
//TODO update to work with floats - needs FLOAT_XOR to be written

void build_hamming(int num_inputs, int input_length, char *circuit_file, int task)
{
	int m = M_HD_;

	int q = Q_HD_ + Q_FLOAT_;	//max num gates
	int r = 8 * q;	//max num wires

	int cf_offset = sprintf(circuit_file, "%sbio_auth_hd_", CIRCUIT_DIR_);

	//see init_GC() macro for more declarations
	init_GC_bio_auth();

	int out_xor[feature_vector_length];

	MIXED_OP_Circuit(&garbledCircuit, &garblingContext, n, XOR, init_inputs, out_xor);
	COUNTBITS_Circuit(&garbledCircuit, &garblingContext, feature_vector_length, out_xor, final_outputs);

	if (Malicious_Security_)
	{
		verify_commitment()
	}

	finalize_GC_bio_auth();
}




//uses the recursive squaring routine SQUARE_2R_G_Circuit() for the multiplication step
//comparison is handled in finalize_GC()  in bio_common.h
//ints are expected to have enough output bits to avoid overflow
//hence comparison can take place over the positive "unbounded" integers

//TODO update to work with floats

void build_euclidean(int num_inputs, int input_length, char *circuit_file, int task)
{
	int m = M_ED_;

	int q = Q_ED_ + Q_FLOAT_;	//max num gates
	int r = 8 * q;	//max num wires

	int stopping_split = 4;	//max recursion; lower == deeper

	int cf_offset = sprintf(circuit_file, "%sbio_auth_ed_", CIRCUIT_DIR_);

	//see init_GC() macro for more declarations
	init_GC_bio_auth();

	int one = 1;
	int zero = 0;

	SET_CONST_FLOAT_CAST_Circuit(&garbledCircuit, &garblingContext, (float) (1 << 6), distance_threshold);

	threshold_comp_type = LES;

	int m_sum = input_length + lg_flr(num_inputs);
	int compr_dot_prod_runsqr[m];
	int compr_dot_prod_enrlsqr[m];
	int compr_dot_prod_runenrl[m];
	int compr_sum_runtime[m_sum];
	int compr_sum_enrollment[m_sum];

	SETCONST_Circuit(&garbledCircuit, &garblingContext, m_sum, &zero, compr_sum_runtime);
	SETCONST_Circuit(&garbledCircuit, &garblingContext, m_sum, &zero, compr_sum_enrollment);

	SUM_Circuit(&garbledCircuit, &garblingContext, num_inputs, input_length, runtime_biom_input.feature_vector, compr_sum_runtime);
	SUM_Circuit(&garbledCircuit, &garblingContext, num_inputs, input_length, enrollment_biom_input.feature_vector, compr_sum_enrollment);
	DOTPROD_Circuit_2I(&garbledCircuit, &garblingContext, num_inputs, input_length, runtime_biom_input.feature_vector, runtime_biom_input.feature_vector, compr_dot_prod_runsqr);
	DOTPROD_Circuit_2I(&garbledCircuit, &garblingContext, num_inputs, input_length, runtime_biom_input.feature_vector, enrollment_biom_input.feature_vector, compr_dot_prod_enrlsqr);
	DOTPROD_Circuit_2I(&garbledCircuit, &garblingContext, num_inputs, input_length, enrollment_biom_input.feature_vector, enrollment_biom_input.feature_vector, compr_dot_prod_runenrl);

	int runrng_squared[SINGLE_LENGTH];
	int enrlrng_squared[SINGLE_LENGTH];
	int runminrng[SINGLE_LENGTH];
	int negrunminrng[SINGLE_LENGTH];

	FLOAT_SQUARE_Circuit(&garbledCircuit, &garblingContext, runtime_range, runrng_squared);
	FLOAT_SQUARE_Circuit(&garbledCircuit, &garblingContext, enroll_range, enrlrng_squared);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runtime_range, runtime_min, runminrng);
	FLOAT_SHIFT_Circuit(&garbledCircuit, &garblingContext, 1, LEFT, INFTY_EQ_NAN, runminrng, runminrng);
	FLOAT_NEG_Circuit(&garbledCircuit, &garblingContext, runminrng, negrunminrng);

	int mindiff[SINGLE_LENGTH];
	int shlmindiff[SINGLE_LENGTH];
	int mindiff_squared[SINGLE_LENGTH];
	int float_dot_prod_runsqr[SINGLE_LENGTH];
	int float_dot_prod_enrlsqr[SINGLE_LENGTH];
	int float_dot_prod_runenrl[SINGLE_LENGTH];
	int float_sum_runtime[SINGLE_LENGTH];
	int float_sum_enrollment[SINGLE_LENGTH];
	int float_num_inputs[SINGLE_LENGTH];
	int float_prod_1[SINGLE_LENGTH];
	int in_sum[6 * SINGLE_LENGTH];

	memcpy(&in_sum[0], enrollment_biom_input.vector_min, SINGLE_LENGTH * sizeof(int));
	memcpy(&in_sum[SINGLE_LENGTH], runtime_biom_input.vector_min, SINGLE_LENGTH * sizeof(int));
	FLOAT_NEG_Circuit(&garbledCircuit, &garblingContext, &in_sum[SINGLE_LENGTH], &in_sum[SINGLE_LENGTH]);
	SUM_Circuit(&garbledCircuit, &garblingContext, 2, input_length, in_sum, mindiff);
	FLOAT_SHIFT_Circuit(&garbledCircuit, &garblingContext, 1, LEFT, INFTY_EQ_NAN, mindiff, shlmindiff);
	FLOAT_SQUARE_Circuit(&garbledCircuit, &garblingContext, mindiff, mindiff_squared);

	INT_TO_FLOAT_Circuit(&garbledCircuit, &garblingContext, m, compr_dot_prod_runsqr, float_dot_prod_runsqr);
	INT_TO_FLOAT_Circuit(&garbledCircuit, &garblingContext, m, compr_dot_prod_enrlsqr, float_dot_prod_enrlsqr);
	INT_TO_FLOAT_Circuit(&garbledCircuit, &garblingContext, m, compr_dot_prod_runenrl, float_dot_prod_runenrl);
	INT_TO_FLOAT_Circuit(&garbledCircuit, &garblingContext, m_sum, compr_sum_runtime, float_sum_runtime);
	INT_TO_FLOAT_Circuit(&garbledCircuit, &garblingContext, m_sum, compr_sum_enrollment, float_sum_enrollment);

	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runrng_squared, float_dot_prod_runsqr, &in_sum[0]);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, enrlrng_squared, float_dot_prod_enrlsqr, &in_sum[SINGLE_LENGTH]);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, float_dot_prod_runenrl, negrunminrng, &in_sum[2 * SINGLE_LENGTH]);

	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, enrollment_biom_input.vector_range, shlmindiff, float_prod_1);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, float_prod_1, float_sum_enrollment, &in_sum[3 * SINGLE_LENGTH]);

	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runtime_biom_input.vector_range, shlmindiff, float_prod_1);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, float_prod_1, float_sum_runtime, &in_sum[4 * SINGLE_LENGTH]);
	FLOAT_NEG_Circuit(&garbledCircuit, &garblingContext, &in_sum[4 * SINGLE_LENGTH], &in_sum[4 * SINGLE_LENGTH]);

	SET_CONST_FLOAT_CAST_Circuit(&garbledCircuit, &garblingContext, (float) num_inputs, float_num_inputs);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, float_num_inputs, mindiff_squared, &in_sum[5 * SINGLE_LENGTH]);

	FLOAT_SUM_Circuit(&garbledCircuit, &garblingContext, 6, in_sum, dist_func_outputs);

	int valid_norm;

	//normalization check

	int runmin_squared[SINGLE_LENGTH];

	FLOAT_SQUARE_Circuit(&garbledCircuit, &garblingContext, runtime_min, runmin_squared);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runminrng, float_sum_runtime, &in_sum[0]);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runrng_squared, float_dot_prod_runsqr, &in_sum[SINGLE_LENGTH]);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runmin_squared, float_num_inputs, &in_sum[2 * SINGLE_LENGTH]);

	int norm_check_outputs[SINGLE_LENGTH];
	FLOAT_SUM_Circuit(&garbledCircuit, &garblingContext, 3, in_sum, norm_check_outputs);

	int float_one[SINGLE_LENGTH];
	SET_CONST_FLOAT_CAST_Circuit(&garbledCircuit, &garblingContext, (float) 1, float_one);

	FLOAT_CMP_Circuit_2I(&garbledCircuit, &garblingContext, EQ, INFTY_EQ_NAN, float_one, norm_check_outputs, &valid_norm);

	final_outputs[1] = valid_norm;

	if (Malicious_Security_)
	{
		verify_commitment();
	}

	finalize_GC_bio_auth();
}




void build_cosine(int num_inputs, int input_length, char *circuit_file, int task) {

	int m = M_CS_;			//int CS output size

	int q = Q_CS_ + Q_FLOAT_;	//max num gates
	int r = 8 * q;				//max num wires

	int cf_offset = sprintf(circuit_file, "%sbio_auth_cs_", CIRCUIT_DIR_);

	init_GC_bio_auth();

	int one = 1;
	int zero = 0;

	SET_CONST_FLOAT_CAST_Circuit(&garbledCircuit, &garblingContext, (float) (1 - (1 << 6)), distance_threshold);

	threshold_comp_type = GRT;

	int m_sum = input_length + lg_flr(num_inputs);
	int compr_dot_prod[m];
	int compr_sum_runtime[m_sum];
	int compr_sum_enrollment[m_sum];

	SETCONST_Circuit(&garbledCircuit, &garblingContext, m_sum, &zero, compr_sum_runtime);
	SETCONST_Circuit(&garbledCircuit, &garblingContext, m_sum, &zero, compr_sum_enrollment);

	SUM_Circuit(&garbledCircuit, &garblingContext, num_inputs, input_length, runtime_biom_input.feature_vector, compr_sum_runtime);
	SUM_Circuit(&garbledCircuit, &garblingContext, num_inputs, input_length, enrollment_biom_input.feature_vector, compr_sum_enrollment);
	DOTPROD_Circuit_2I(&garbledCircuit, &garblingContext, num_inputs, input_length, runtime_biom_input.feature_vector, enrollment_biom_input.feature_vector, compr_dot_prod);

	int float_dot_prod[SINGLE_LENGTH];
	int float_sum_runtime[SINGLE_LENGTH];
	int float_sum_enrollment[SINGLE_LENGTH];
	int float_num_inputs[SINGLE_LENGTH];
	int float_prod_1[SINGLE_LENGTH];
	int float_prod_2[SINGLE_LENGTH];
	int float_prod_3[SINGLE_LENGTH];
	int float_prod_4[SINGLE_LENGTH];
	int in_sum[4 * SINGLE_LENGTH];

	INT_TO_FLOAT_Circuit(&garbledCircuit, &garblingContext, m, compr_dot_prod, float_dot_prod);
	INT_TO_FLOAT_Circuit(&garbledCircuit, &garblingContext, m_sum, compr_sum_runtime, float_sum_runtime);
	INT_TO_FLOAT_Circuit(&garbledCircuit, &garblingContext, m_sum, compr_sum_enrollment, float_sum_enrollment);

	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runtime_biom_input.vector_range, float_dot_prod, float_prod_1);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, enrollment_biom_input.vector_range, float_prod_1, &in_sum[0]);

	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runtime_biom_input.vector_min, float_sum_runtime, float_prod_2);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, enrollment_biom_input.vector_range, float_prod_2, &in_sum[SINGLE_LENGTH]);

	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runtime_biom_input.vector_range, float_sum_enrollment, float_prod_3);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, enrollment_biom_input.vector_min, float_prod_3, &in_sum[2 * SINGLE_LENGTH]);

	SET_CONST_FLOAT_CAST_Circuit(&garbledCircuit, &garblingContext, (float) num_inputs, float_num_inputs);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runtime_biom_input.vector_min, float_num_inputs, float_prod_4);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, enrollment_biom_input.vector_min, float_prod_4, &in_sum[3 * SINGLE_LENGTH]);

	FLOAT_SUM_Circuit(&garbledCircuit, &garblingContext, 4, in_sum, dist_func_outputs);

	int valid_norm;

	//normalization check

	int runrng_squared[SINGLE_LENGTH];
	int runmin_squared[SINGLE_LENGTH];
	int runminrng[SINGLE_LENGTH];


	FLOAT_SQUARE_Circuit(&garbledCircuit, &garblingContext, runtime_range, runrng_squared);
	FLOAT_SQUARE_Circuit(&garbledCircuit, &garblingContext, runtime_min, runmin_squared);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runtime_range, runtime_min, runminrng);

	DOTPROD_Circuit_2I(&garbledCircuit, &garblingContext, num_inputs, input_length, runtime_biom_input.feature_vector, runtime_biom_input.feature_vector, compr_dot_prod);

	FLOAT_SHIFT_Circuit(&garbledCircuit, &garblingContext, 1, LEFT, INFTY_EQ_NAN, runminrng, runminrng);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runminrng, float_sum_runtime, &in_sum[0]);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runrng_squared, float_dot_prod, &in_sum[SINGLE_LENGTH]);
	FLOAT_MUL_Circuit_2I(&garbledCircuit, &garblingContext, runmin_squared, float_num_inputs, &in_sum[2 * SINGLE_LENGTH]);

	int norm_check_outputs[SINGLE_LENGTH];
	FLOAT_SUM_Circuit(&garbledCircuit, &garblingContext, 3, in_sum, norm_check_outputs);

	int float_one[SINGLE_LENGTH];
	SET_CONST_FLOAT_CAST_Circuit(&garbledCircuit, &garblingContext, (float) 1, float_one);

	FLOAT_CMP_Circuit_2I(&garbledCircuit, &garblingContext, EQ, INFTY_EQ_NAN, float_one, norm_check_outputs, &valid_norm);

	final_outputs[1] = valid_norm;

	if (Malicious_Security_)
	{
		verify_commitment();
	}

	finalize_GC_bio_auth();
}






