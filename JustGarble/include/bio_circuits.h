
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


#ifndef _OUR_CIRCUITS_
#define _OUR_CIRCUITS_

#include "../include/justGarble.h"

#define MANTISSA 0
#define MANT_ZERO_FLAG 23
#define EXPONENT 24
#define EXP_ZERO_FLAG 32
#define EXP_SPEC_FLAG 33
#define ZERO_FLAG 34
#define SIGN 35

#define SINGLE_LENGTH (SIGN + 1)

#define INFTY_NEQ_NAN 0
#define INFTY_EQ_NAN 1

#define ADDITION 0
#define MULTIPLICATION 1
#define SHIFT 2

#define OVERFLOW 0
#define NO_OVERFLOW 1
#define UNDERFLOW 2
#define NO_UNDERFLOW 3

#define BRANCH_A 0
#define BRANCH_B 1

#define FROM_LSB 0
#define FROM_MSB 1

#define MASK_ONLY 0
#define MASK_AND_INDEX 1

#define LEQ 0
#define GEQ 1
#define GRT 2
#define LES 3
#define NEQ 4
#define EQ 5

#define A_LEQ_B 0
#define B_LEQ_A 1
#define B_LES_A 2
#define A_LES_B 3
#define A_NEQ_B 4
#define A_EQ_B 5


int SETCONST_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* constant, int* outputs);
int MIXED_OP_Gate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int op_type, int input0, int input1, int *output);
int MIXED_OP_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int op_type, int* inputs, int* outputs);
int MIXED_OP_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int op_type, int* inputA, int* inputB, int* outputs);

int ADD22_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int* outputs);
int ADD32_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int in_carry, int* outputs);
int ADD_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int oflow_type, int* inputs, int* outputs);
int ADD_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int oflow_type, int* inputA, int* inputB, int* outputs);
int SUM_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int num_inputs, int input_length, int *inputs, int *outputs);

int BITADD_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int oflow_type, int* inputs, int* outputs);
int BITADD_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int oflow_type, int* inputA, int inputB, int* outputs);

int NOT_Gate2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int *output);
int NOT_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs);

int INC_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int oflow_type, int* inputs, int* outputs);
int NEG_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs);
int SUB22_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int* outputs);
int BITSUB_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputs, int* outputs);
int BITSUB_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputA, int inputB, int* outputs);
int SUB_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputs, int* outputs);
int SUB_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputA, int* inputB, int* outputs);
int SUB_Circuit3(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputs, int* outputs);
int SUB_Circuit3_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputA, int* inputB, int* outputs);

int REPR_SW_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int num_inputs, int input_length, int* inputs, int* outputs);

int ADD_Circuit_2R(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int m0, int input_length, int sing_idx, int* inputs, int* outputs);
int COUNTBITS_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs);

int PREFIX_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int op_type, int input_begin, int input_end, int output_begin, int in_direction, int out_direction, int* inputs, int* outputs);
int INV_PREFIX_XOR_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int input_begin, int input_end, int output_begin, int in_direction, int out_direction, int* inputs, int* outputs);
int SHIFT_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int shift_amount, int direction, int shift_type, int sign, int* inputs, int* outputs);
int OBLV_SHIFT_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int direction, int shift_type, int sign, int max_shift, int* oblv_shift_amt, int* inputs, int* outputs);

int DEC_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputs, int* outputs);
int MSB_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int return_val, int* inputs, int* msb_mask_out, int* msb_index_out, int *is_not_zero);
int CMP_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int comp_type, int* inputs, int* outputs);
int CMP_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int comp_type, int* inputA, int* inputB, int* outputs);
int MINIMAX_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputA, int* inputB, int* outputs);

int BITMUL_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputA, int inputB, int* outputs);
int MUL_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int *inputs, int *outputs);
int MUL_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int *inputA, int *inputB, int *outputs);
int DOTPROD_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int num_inputs, int input_length, int *inputs, int *outputs);
int DOTPROD_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int num_inputs, int input_length, int *inputA, int *inputB, int *outputs);
int SQUARE_2R_G_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs, int stopping_split);
int KMUL_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs, int stopping_split);


//single width float routines

int SET_RAW_FLOAT_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int* inputs, int* outputs);
int SET_CONST_FLOAT_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int mantissa, int exponent, int sign, int* outputs);
int SET_CONST_FLOAT_CAST_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, float const_input, int* outputs);
int INT_TO_FLOAT_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs);

int FLOAT_SUM_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int num_inputs, int *inputs, int *outputs);
int FLOAT_NEG_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int *inputA, int *outputs);
int FLOAT_MUL_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int *inputA, int *inputB, int *outputs);
int FLOAT_SQUARE_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int *inputA, int *outputs);
int FLOAT_CMP_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int comp_type, int infinity_type, int *inputA, int *inputB, int* outputs);
int FLOAT_SHIFT_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int shift_amount, int direction, int infinity_type, int *inputA, int *outputs);

#endif

