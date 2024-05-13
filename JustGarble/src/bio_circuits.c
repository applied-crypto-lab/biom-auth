
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
#include "../include/circuits.h"
#include "../include/gates.h"
#include "../include/bio_common.h"
#include "../include/bio_circuits.h"
#include "../include/bio_commit_funcs.h"


int mask = -1;
int zero = 0;
int one = 1;

//hardwrires a predefined fixed constant into outputs from an array of input ints

int SETCONST_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* constants, int* outputs)
{

	int i = 0;
	int j = 0;
	int bit_mask = 1;

	while ((i * 8 * sizeof(int)) + j < n)
	{
		int this_bit_is_set = bit_mask & constants[i];
		int this_is_msb = ((i * 8 * sizeof(int)) + j == n - 1);
		if ((this_bit_is_set) ^ (this_is_msb && (Int_Representation_ == SIGNED)))
			outputs[(i * 8 * sizeof(int)) + j] = fixedOneWire(garbledCircuit, garblingContext);
		else
			outputs[(i * 8 * sizeof(int)) + j] = fixedZeroWire(garbledCircuit, garblingContext);

		j++;
		bit_mask <<= 1;
		if (j == 8 * sizeof(int))
		{
			bit_mask = 1;
			j = 0;
			i++;
		}
	}
}




//NOTE op_type in {AND, OR, XOR}

//CAUTION the standard approach in JG is to initialize a gate output wire with a call to getNextWire() prior to passing into the gate building function
//CAUTION however, since a fresh wire may not be needed, this generation happens within MIXED_OP_Gate() and thus should not be performed prior to calling
//CAUTION as a consequence, unlike with standard gate functions, the output wire is passed as a pointer

int MIXED_OP_Gate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int op_type, int input0, int input1, int *output)
{
	int input0_is_zero = garblingContext->fixedWires[input0] == FIXED_ZERO_WIRE;
	int input1_is_zero = garblingContext->fixedWires[input1] == FIXED_ZERO_WIRE;
	int input0_is_one = garblingContext->fixedWires[input0] == FIXED_ONE_WIRE;
	int input1_is_one = garblingContext->fixedWires[input1] == FIXED_ONE_WIRE;

	if (input0_is_zero || input0_is_one || input1_is_zero || input1_is_one)
	{
		if (op_type == AND)
		{
			if (input0_is_zero || input1_is_zero)
				*output = fixedZeroWire(garbledCircuit, garblingContext);
			else if (input0_is_one)
				*output = input1;
			else
				*output = input0;
		}
		else if (op_type == OR)
		{
			if (input0_is_one || input1_is_one)
				*output = fixedOneWire(garbledCircuit, garblingContext);
			else if (input0_is_zero)
				*output = input1;
			else
				*output = input0;
		}
		else if (op_type == XOR)
		{
			if (input0_is_zero)
				*output = input1;
			else if (input1_is_zero)
				*output = input0;
			else
			{
				if (input0_is_one && input1_is_one)
					*output = fixedZeroWire(garbledCircuit, garblingContext);
				else
				{
					garbledCircuit->qxor++;
					*output = getNextWire(garblingContext);
					XORGate(garbledCircuit, garblingContext, input0, input1, *output);
				}
			}
		}
	}
	else if (input0 == input1)
	{
		if ((op_type == AND) || (op_type == OR))
			*output = input0;
		else if (op_type == XOR)
			*output = fixedZeroWire(garbledCircuit, garblingContext);
	}
	else
	{
		*output = getNextWire(garblingContext);
		if (op_type == AND)
		{
			garbledCircuit->qand++;
			ANDGate(garbledCircuit, garblingContext, input0, input1, *output);
		}
		else if (op_type == OR)
		{
			garbledCircuit->qor++;
			ORGate(garbledCircuit, garblingContext, input0, input1, *output);
		}
		else if (op_type == XOR)
		{
			garbledCircuit->qxor++;
			XORGate(garbledCircuit, garblingContext, input0, input1, *output);
		}
	}
}



//NOTE op_type in {AND, OR, XOR}

int MIXED_OP_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int op_type, int* inputs, int* outputs)
{
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, n, op_type, inputs, &inputs[n/2], outputs);
}


int MIXED_OP_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int op_type, int* inputA, int* inputB, int* outputs)
{
	int split = n/2;
	int inputA_copy[split];
	int inputB_copy[split];
	memcpy(inputA_copy, inputA, split * sizeof(int));
	memcpy(inputB_copy, inputB, split * sizeof(int));

	for (int i = 0; i < split; i++)
	{
		MIXED_OP_Gate(garbledCircuit, garblingContext, op_type, inputA_copy[i], inputB_copy[i], &outputs[i]);
	}
}



int ADD22_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int* outputs)
{
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, input0, input1, &outputs[0]);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, input0, input1, &outputs[1]);
}



int ADD32_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int in_carry, int* outputs)
{
	int wire1;
	int wire2;
	int wire3;

	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, input0, in_carry, &wire1);
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, input0, input1, &wire2);
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, in_carry, wire2, &outputs[0]);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, wire1, wire2, &wire3);
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, input0, wire3, &outputs[1]);
}



//computes addition where inputs a and b have length n, optionally provides final (overflow) carry-out bit

int ADD_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int oflow_type, int* inputs, int* outputs)
{
	ADD_Circuit_2I(garbledCircuit, garblingContext, n, oflow_type, inputs, &inputs[n/2], outputs);
}


int ADD_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int oflow_type, int* inputA, int* inputB, int* outputs)
{
	int split = n / 2;
	int in_carry;
	int out_add[2];

	int inputA_copy[split];
	int inputB_copy[split];
	memcpy(inputA_copy, inputA, split * sizeof(int));
	memcpy(inputB_copy, inputB, split * sizeof(int));

	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[0], inputB_copy[0], &outputs[0]);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, inputA_copy[0], inputB_copy[0], &in_carry);

	for (int i = 1; i < split - 1; i++) {
		ADD32_Circuit2(garbledCircuit, garblingContext, inputA_copy[i], inputB_copy[i], in_carry, out_add);
		outputs[i] = out_add[0];
		in_carry = out_add[1];
	}

	if (oflow_type == OVERFLOW)
		ADD32_Circuit2(garbledCircuit, garblingContext, inputA_copy[split - 1], inputB_copy[split - 1], in_carry, &outputs[split - 1]);
	else
	{
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[split - 1], in_carry, &outputs[split - 1]);
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputB_copy[split - 1], outputs[split - 1], &outputs[split - 1]);
	}
}



int SUM_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int num_inputs, int input_length, int *inputs, int *outputs)
{
	if (num_inputs < 2)
	{
		memcpy(outputs, inputs, num_inputs * input_length * sizeof(int));
		return 0;
	}

	int num_overflow_bits = 1 + lg_flr(num_inputs - 1);
	int output_length = input_length + num_overflow_bits;
	int add_pairs[num_inputs][output_length];
	int zero = 0;

	for (int i = 0; i < num_inputs; i++)
	{
		memcpy(&add_pairs[i], &inputs[input_length * i], input_length * sizeof(int));
		SETCONST_Circuit(garbledCircuit, garblingContext, num_overflow_bits, &zero, &add_pairs[i][input_length]);
	}

	int l = 1;
	int num_pairs = num_inputs;

	while (num_pairs > 1)
	{
		if (num_pairs % 2)
			ADD_Circuit_2I(garbledCircuit, garblingContext, 2 * output_length, NO_OVERFLOW,
						   (int *) &add_pairs[0], (int *) &add_pairs[l * (num_pairs - 1)], (int *) &add_pairs[0]);
			num_pairs >>= 1;
		for (int i = 0; i < num_pairs; i++)
			ADD_Circuit_2I(garbledCircuit, garblingContext, 2 * output_length, NO_OVERFLOW,
						   (int *) &add_pairs[l * (2*i)], (int *) &add_pairs[l * (2*i + 1)], (int *) &add_pairs[l * (2*i)]);
			l *= 2;
	}

	memcpy(outputs, &add_pairs[0], output_length * sizeof(int));
}


//computes addition where input b is a single bit, optionally provides final (overflow) carry-out bit
//input a: inputs[0...n-1], input b: input[n], output length: n+1

int BITADD_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int oflow_type, int* inputs, int* outputs)
{
	int inputB_copy = inputs[n];
	BITADD_Circuit_2I(garbledCircuit, garblingContext, n, oflow_type, inputs, inputB_copy, outputs);
}


int BITADD_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int oflow_type, int* inputA, int inputB, int* outputs)
{
	int out_add[2];
	int split = n;
	int in_carry = inputB;

	int inputA_copy[split];
	memcpy(inputA_copy, inputA, split * sizeof(int));

	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[0], inputB, &outputs[0]);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, inputA_copy[0], inputB, &in_carry);

	for (int i = 1; i < split - 1; i++) {
		ADD22_Circuit2(garbledCircuit, garblingContext, inputA_copy[i], in_carry, out_add);
		outputs[i] = out_add[0];
		in_carry = out_add[1];
	}

	if (oflow_type == OVERFLOW)
		ADD22_Circuit2(garbledCircuit, garblingContext, inputA_copy[split - 1], in_carry, &outputs[split - 1]);
	else
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[split - 1], in_carry, &outputs[split - 1]);
}



int NOT_Gate2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int *output)
{
	int input0_is_zero = garblingContext->fixedWires[input0] == FIXED_ZERO_WIRE;
	int input0_is_one = garblingContext->fixedWires[input0] == FIXED_ONE_WIRE;

	if (input0_is_zero)
		*output = fixedOneWire(garbledCircuit, garblingContext);
	else if (input0_is_one)
		*output = fixedZeroWire(garbledCircuit, garblingContext);
	else
	{
		garbledCircuit->qnot++;
		*output = getNextWire(garblingContext);
		NOTGate(garbledCircuit, garblingContext, input0, *output);
	}
}



//NOT circuit which uses XOR by fixed one wire instead of built in NOTGate

int NOT_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs)
{
	int input_copy[n];
	memcpy(input_copy, inputs, n * sizeof(int));

	for (int i = 0; i < n; i++)
	{
		NOT_Gate2(garbledCircuit, garblingContext, input_copy[i], &outputs[i]);
	}
}


//increment circuit
//overflow type in OVERFLOW, NO_OVERFLOW
int INC_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int oflow_type, int* inputs, int* outputs)
{
	int input_copy[n+1];
	memcpy(input_copy, inputs, n*sizeof(int));
	input_copy[n] = fixedOneWire(garbledCircuit, garblingContext);

	if (oflow_type == OVERFLOW)
		BITADD_Circuit2(garbledCircuit, garblingContext, n, OVERFLOW, input_copy, outputs);
	else
		BITADD_Circuit2(garbledCircuit, garblingContext, n, NO_OVERFLOW, input_copy, outputs);
}


//twos-complement negation circuit

int NEG_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs)
{
	int out_not[n];

	NOT_Circuit2(garbledCircuit, garblingContext, n, inputs, out_not);
	INC_Circuit2(garbledCircuit, garblingContext, n, NO_OVERFLOW, out_not, outputs);
}



int SUB22_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int* outputs)
{
	int not_input0;
	NOT_Gate2(garbledCircuit, garblingContext, input0, &not_input0);
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, input0, input1, &outputs[0]);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, not_input0, input1, &outputs[1]);
}


int SUB32_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int in_carry, int* outputs)
{
	int wire1;
	int wire2;
	int wire3;
	int not_input0;

	NOT_Gate2(garbledCircuit, garblingContext, input0, &not_input0);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, in_carry, input1, &wire1);
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, in_carry, input1, &wire2);
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, input0, wire2, &outputs[0]);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, not_input0, wire2, &wire3);
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, wire1, wire3, &outputs[1]);
}


//computes addition where input b is a single bit, optionally provides final (overflow) carry-out bit
//input a: inputs[0...n-1], input b: input[n], output length: n+1

int BITSUB_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputs, int* outputs)
{
	int inputB_copy = inputs[n];
	BITSUB_Circuit_2I(garbledCircuit, garblingContext, n, uflow_type, inputs, inputB_copy, outputs);
}


int BITSUB_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputA, int inputB, int* outputs)
{
	int out_sub[2];
	int split = n;
	int in_carry = inputB;
	int not_input0;

	int inputA_copy[split];
	memcpy(inputA_copy, inputA, split * sizeof(int));

	NOT_Gate2(garbledCircuit, garblingContext, inputA_copy[0], &not_input0);
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[0], inputB, &outputs[0]);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, not_input0, inputB, &in_carry);

	for (int i = 1; i < split - 1; i++) {
		SUB22_Circuit2(garbledCircuit, garblingContext, inputA_copy[i], in_carry, out_sub);
		outputs[i] = out_sub[0];
		in_carry = out_sub[1];
	}

	if (uflow_type == UNDERFLOW)
		SUB22_Circuit2(garbledCircuit, garblingContext, inputA_copy[split - 1], in_carry, &outputs[split - 1]);
	else
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[split - 1], in_carry, &outputs[split - 1]);
}




//given A = inputs[0] and B = inputs[split], outputs = A - B

int SUB_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputs, int* outputs)
{
	SUB_Circuit_2I(garbledCircuit, garblingContext, n, uflow_type, inputs, &inputs[n/2], outputs);
}


int SUB_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputA, int* inputB, int* outputs)
{
	int split = n / 2;
	int negB[n];

	int inputA_copy[split];
	memcpy(inputA_copy, inputA, split * sizeof(int));

	NEG_Circuit(garbledCircuit, garblingContext, split, inputB, negB);
	ADD_Circuit_2I(garbledCircuit, garblingContext, n, uflow_type - (UNDERFLOW - OVERFLOW), inputA_copy, negB, outputs);
}


int SUB_Circuit3(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputs, int* outputs)
{
	SUB_Circuit3_2I(garbledCircuit, garblingContext, n, uflow_type, inputs, &inputs[n/2], outputs);
}


int SUB_Circuit3_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputA, int* inputB, int* outputs)
{
	int split = n / 2;
	int in_carry;
	int out_sub[2];
	int not_inputA0;

	int inputA_copy[split];
	int inputB_copy[split];
	memcpy(inputA_copy, inputA, split * sizeof(int));
	memcpy(inputB_copy, inputB, split * sizeof(int));

	NOT_Gate2(garbledCircuit, garblingContext, inputA_copy[0], &not_inputA0);
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[0], inputB_copy[0], &outputs[0]);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, not_inputA0, inputB_copy[0], &in_carry);

	for (int i = 1; i < split - 1; i++) {
		SUB32_Circuit2(garbledCircuit, garblingContext, inputA_copy[i], inputB_copy[i], in_carry, out_sub);
		outputs[i] = out_sub[0];
		in_carry = out_sub[1];
	}

	if (uflow_type == OVERFLOW)
		SUB32_Circuit2(garbledCircuit, garblingContext, inputA_copy[split - 1], inputB_copy[split - 1], in_carry, &outputs[split - 1]);
	else
	{
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[split - 1], in_carry, &outputs[split - 1]);
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputB_copy[split - 1], outputs[split - 1], &outputs[split - 1]);
	}
}



//toggles between signed and unsigned representations by toggling msb, as per C99 standard

int REPR_SW_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int num_inputs, int input_length, int* inputs, int* outputs)
{
	for (int i = 0; i < num_inputs; i++) {
		NOT_Gate2(garbledCircuit, garblingContext, inputs[(i+1)*input_length - 1], &outputs[(i+1)*input_length - 1]);
		memcpy(&outputs[i*input_length], &inputs[i*input_length], (input_length - 1) * sizeof(int));
	}

	//TODO	make better system-wide way to track this
	//TODO	that is, either ensure that all inputs are toggled together
	//TODO	or associate representation to each sub-input, e.g. maybe package inputs in structs
	//Int_Representation_ = 1 - Int_Representation_;

}



//used as a subroutine of COUNTBITS
//expects two vectors of inputs of length s each, with each input having length input_length, and adds each pairwise

int ADD_Circuit_2R(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int m0, int input_length, int sing_idx, int* inputs, int* outputs)
{
	//input_length is wide enough for two values being added, out_len for the single output of this operation
	int num_inputs = m0 / input_length;
	int out_len = (input_length / 2) + 1;

	for (int i = 0; i < num_inputs; i++) {
		int temp[out_len + 2];
		ADD_Circuit2(garbledCircuit, garblingContext, input_length, OVERFLOW, &inputs[i * input_length], temp);
		temp[out_len] = inputs[sing_idx + i];
		BITADD_Circuit2(garbledCircuit, garblingContext, NO_OVERFLOW, out_len, temp, &outputs[i * out_len]);
	}
}



//counts number of set bits in inputs
//used as a subroutine of Hamming distance routine
//NOTE leaving out one singleton bit per round and adding back later allows computation to be contained within one fewer bit than otherwise
//NOTE not exercising this optimization is equivalent to simply calling SUM_Circuit(garbledCircuit, garblingContext, n, 1, inputs, outputs);

int COUNTBITS_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs)
{
	int in_len_rd = 2;
	int num_inp_rd = n / 4;
	int m = num_inp_rd * in_len_rd;
	int singleton_index = n / 2;

	int in_add[n];
	int out_add[n];

	for (int i = 0; i < n; i++) {
		in_add[i] = inputs[i];
	}

	while (num_inp_rd > 0) {

		ADD_Circuit_2R(garbledCircuit, garblingContext, m, in_len_rd, singleton_index, in_add, out_add);
		for (int i = 0; i < m; i++) {
			in_add[i] = out_add[i];
		}

		singleton_index += num_inp_rd;
		in_len_rd += 2;
		num_inp_rd /= 2;
		m = num_inp_rd * in_len_rd;
	}

	in_add[in_len_rd / 2] = inputs[n - 1];

	BITADD_Circuit2(garbledCircuit, garblingContext, in_len_rd / 2, OVERFLOW, in_add, outputs);
}



//calculates prefix-operation for op_type in {AND, OR, XOR}
//inputs[input_begin] is copied to outputs[output_begin], and the prefix op moves in in_direction
//outputs move in out_direction, with modular wraparound on indices in all cases (cyclic shift)
//in_, out_direction in {FROM_LSB, FROM_MSB}

int PREFIX_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int op_type, int input_begin, int input_end, int output_begin, int in_direction, int out_direction, int* inputs, int* outputs)
{
	int input_copy[n];
	memcpy(input_copy, inputs, n * sizeof(int));

	int out_idx = output_begin;
	int in_idx = input_begin;
	int next_wire = input_copy[in_idx];

	while (in_idx != input_end)
	{
		outputs[out_idx] = next_wire;
		in_idx = in_direction == FROM_LSB ? (n + in_idx + 1) % n : (n + in_idx - 1) % n;
		MIXED_OP_Gate(garbledCircuit, garblingContext, op_type, outputs[out_idx], input_copy[in_idx], &next_wire);
		out_idx = out_direction == FROM_LSB ? (n + out_idx + 1) % n : (n + out_idx - 1) % n;
	}
	outputs[out_idx] = next_wire;

}



// prefix-XOR is a cyclic function under iteration
// its inverse in this context is the function which outputs the XOR of each adjacent pair of input bits
// equivalently, inverse prefix xor(lsb, a) = a XOR (a << 1) and inverse prefix xor(msb, a) = a XOR (a >> 1)

int INV_PREFIX_XOR_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int input_begin, int input_end, int output_begin, int in_direction, int out_direction, int* inputs, int* outputs)
{
	int input_copy[n];
	memcpy(input_copy, inputs, n * sizeof(int));

	int out_idx = output_begin;
	int in_idx = input_begin;
	int next_wire = input_copy[in_idx];
	int next_in_idx = in_idx;

	while (next_in_idx != input_end)
	{
		outputs[out_idx] = next_wire;
		int prev_in_idx = next_in_idx;
		next_in_idx = in_direction == FROM_LSB ? (n + next_in_idx + 1) % n : (n + next_in_idx - 1) % n;
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, input_copy[prev_in_idx], input_copy[next_in_idx], &next_wire);
		out_idx = out_direction == FROM_LSB ? (n + out_idx + 1) % n : (n + out_idx - 1) % n;
	}
	outputs[out_idx] = next_wire;
}



//shifts inputs shift positions to the shift_direction
//shift_type in {TRUNC, CIRCULAR}
//direction in {LEFT, RIGHT}

int SHIFT_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int shift_amount, int direction, int shift_type, int sign, int* inputs, int* outputs)
{
	int j, wrapped;
	int input_copy[n];

	memcpy(input_copy, inputs, n * sizeof(int));

	for (int i = 0; i < n; i++)
	{
		if (direction == LEFT)
		{
			j = i + shift_amount;
			wrapped = j >= n;
		}
		else
		{
			j = i - shift_amount;
			wrapped = j < 0;
		}
		j = (n + j) % n;

		if ((!wrapped) | (shift_type == CIRCULAR))
			outputs[j] = input_copy[i];
		else
		{
			if ((sign == NEGATIVE) && (direction == RIGHT))
				outputs[j] = fixedOneWire(garbledCircuit, garblingContext);
			else
				outputs[j] = fixedZeroWire(garbledCircuit, garblingContext);
		}
	}
}



int OBLV_SHIFT_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int direction, int shift_type, int sign, int max_shift, int* oblv_shift_amt, int* inputs, int* outputs)
{
	int shift_bits = 1 + lg_flr(max_shift);
	int not_oblv_shift_amt[shift_bits];
	NOT_Circuit2(garbledCircuit, garblingContext, shift_bits, oblv_shift_amt, not_oblv_shift_amt);

	int shift_amount = 1;
	int shifted_input[n];
	memcpy(shifted_input, inputs, n * sizeof(int));

	for (int i = 0; i < shift_bits; i++)
	{
		int set_bit_case[n];
		int unset_bit_case[n];
		int prev_input[n];
		memcpy(prev_input, shifted_input, n * sizeof(int));

		SHIFT_Circuit(garbledCircuit, garblingContext, n, shift_amount, direction, shift_type, sign, shifted_input, shifted_input);
		BITMUL_Circuit_2I(garbledCircuit, garblingContext, n, shifted_input, oblv_shift_amt[i], set_bit_case);
		BITMUL_Circuit_2I(garbledCircuit, garblingContext, n, prev_input, not_oblv_shift_amt[i], unset_bit_case);
		MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2*n, XOR, set_bit_case, unset_bit_case, shifted_input);

		shift_amount *= 2;
	}

	memcpy(outputs, shifted_input, n * sizeof(int));
}


//decrement circuit

int DEC_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int uflow_type, int* inputs, int* outputs)
{
	int input_copy[n+1];
	memcpy(input_copy, inputs, n*sizeof(int));
	input_copy[n] = fixedOneWire(garbledCircuit, garblingContext);

	if (uflow_type == UNDERFLOW)
		BITSUB_Circuit2(garbledCircuit, garblingContext, n, OVERFLOW, input_copy, outputs);
	else
		BITSUB_Circuit2(garbledCircuit, garblingContext, n, NO_OVERFLOW, input_copy, outputs);
}



// provides three outputs
// output 1 is the index of the msb of the value in inputs, as an oblivious binary encoding
// e.g. if inputs = {1, 1, 0, 1, 0, 1, 0, 0}, then (assuming n == 8), msb_index_out = {1, 0, 1, 0}
// output 2 is a mask where only the msb is set
// e.g. using above example, msb_mask_out = {0, 0, 0, 0, 0, 1, 0, 0}
// output 3 is a wire containing a 1 iff at least one input bit is set

int MSB_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int return_val, int* inputs, int* msb_mask_out, int* msb_index_out, int *is_not_zero)
{
	int out_pref_1[n + 1];
	int out_pref_2[n + 1];

	PREFIX_Circuit(garbledCircuit, garblingContext, n, OR, n - 1, 0, n - 1, FROM_MSB, FROM_MSB, inputs, out_pref_1);
	out_pref_1[n] = fixedZeroWire(garbledCircuit, garblingContext);
	INV_PREFIX_XOR_Circuit(garbledCircuit, garblingContext, n + 1, 0, n, 0, FROM_LSB, FROM_LSB, out_pref_1, out_pref_2);
	SHIFT_Circuit(garbledCircuit, garblingContext, n + 1, 1, RIGHT, TRUNC, POSITIVE, out_pref_2, out_pref_2);
	memcpy(msb_mask_out, out_pref_2, n * sizeof(int));

	*is_not_zero = out_pref_1[0];

	if (return_val == MASK_ONLY)
		return 0;

	int zero = 0;
	int l = 1 + lg_flr(n - 1);
	SETCONST_Circuit(garbledCircuit, garblingContext, l, &zero, msb_index_out);

	for (int i = 0; i < n; i++)
	{
		int index_repr_in[l];
		int index_repr_out[l];
		SETCONST_Circuit(garbledCircuit, garblingContext, l, &i, index_repr_in);
		BITMUL_Circuit_2I(garbledCircuit, garblingContext, l, index_repr_in, msb_mask_out[i], index_repr_out);
		MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2*l, XOR, index_repr_out, msb_index_out, msb_index_out);
	}
}



//Comparison function which handles eq, neq, les, leq, gre, geq based on runtime value of comp_type
//where A is in inputs[0..split-1], B is in inputs[split..2*split-1]
//We read A CMP B for CMP (comp_type) in {GEQ, LEQ, LES, GRT, NEQ, EQ}
//Alternatively, CMP (comp_type) can be in {B_LEQ_A, A_LEQ_B, A_LES_B, B_LES_A, A_NEQ_B, A_EQ_B}
//CAUTION when comparison type is *not* EQ or NEQ, then there are two output values
//CAUTION in these cases, the requested comparison is in outputs[0], and A NEQ B is in outputs[1]
//NOTE by doing this, all relations between A and B can be obtained with one function call and 4 additional gates

int CMP_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int comp_type, int* inputs, int* outputs)
{
	CMP_Circuit_2I(garbledCircuit, garblingContext, n, comp_type, inputs, &inputs[n/2], outputs);
}

#define handle_int_repr(situation)\
\
if (toggling_sign)\
{\
	if (situation == EXIT)\
	{\
		memcpy(temp_reprsw, outputs, sizeof(int));\
		REPR_SW_Circuit(garbledCircuit, garblingContext, 1, 1, temp_reprsw, outputs);\
	}\
	memcpy(temp_reprsw, inputA, split * sizeof(int));\
	REPR_SW_Circuit(garbledCircuit, garblingContext, 2, split, temp_reprsw, inputA);\
	memcpy(temp_reprsw, inputB, split * sizeof(int));\
	REPR_SW_Circuit(garbledCircuit, garblingContext, 2, split, temp_reprsw, inputB);\
}

int CMP_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int comp_type, int* inputA, int* inputB, int* outputs)
{
	int split = n / 2;
	int testing_eq_only = comp_type & 4;
	int testing_strict_inequality = comp_type & 2;
	int branch = comp_type & 1;

	int out_xor[split];
	int out_pref_1[split + 1];
	int out_pref_2[split + 1];
	int temp_reprsw[n];

	int toggling_sign = Int_Representation_ == SIGNED;

	handle_int_repr(ENTRANCE);

	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, n, XOR, inputA, inputB, out_xor);
	PREFIX_Circuit(garbledCircuit, garblingContext, split, OR, split - 1, 0, split - 1, FROM_MSB, FROM_MSB, out_xor, out_pref_1);

	int is_not_eq = out_pref_1[0];

	if (testing_eq_only) {
		if (comp_type == EQ) {
			NOT_Gate2(garbledCircuit, garblingContext, is_not_eq, &outputs[0]);
		}
		else
			outputs[0] = is_not_eq;

		handle_int_repr(EXIT);
		return 0;
	}

	out_pref_1[split] = fixedZeroWire(garbledCircuit, garblingContext);
	INV_PREFIX_XOR_Circuit(garbledCircuit, garblingContext, split + 1, 0, split, 0, FROM_LSB, FROM_LSB, out_pref_1, out_pref_2);
	SHIFT_Circuit(garbledCircuit, garblingContext, split + 1, 1, RIGHT, TRUNC, POSITIVE, out_pref_2, out_pref_2);

	int in_conj[n];
	int out_conj[split];
	int out_pref_3[split];

	memcpy(in_conj, out_pref_2, split * sizeof(int));
	memcpy(&in_conj[split], branch == 0 ? inputA : inputB, split * sizeof(int));

	MIXED_OP_Circuit(garbledCircuit, garblingContext, n, AND, in_conj, out_conj);
	//NOTE the below operations work using XOR instead of OR only because we know that at most one bit is set in out_conj
	PREFIX_Circuit(garbledCircuit, garblingContext, split, XOR, split - 1, 0, split - 1, FROM_MSB, FROM_MSB, out_conj, out_pref_3);

	if (testing_strict_inequality)
	{
		//A >? B on branch 0, while B >? A on branch 1
		outputs[0] = out_pref_3[0];
	}
	else
	{
		//A <=? B on branch 0, while B <=? A on branch 1
		NOT_Gate2(garbledCircuit, garblingContext, out_pref_3[0], &outputs[0]);
	}

	outputs[1] = is_not_eq;

	handle_int_repr(EXIT);
}



int MINIMAX_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputA, int* inputB, int* outputs)
{
	int split = n / 2;
	int a_les_b;
	int a_geq_b;
	int min_case_1[split];
	int min_case_2[split];
	int max_case_1[split];
	int max_case_2[split];

	CMP_Circuit_2I(garbledCircuit, garblingContext, n, LES, inputA, inputB, &a_les_b);
	NOT_Gate2(garbledCircuit, garblingContext, a_les_b, &a_geq_b);

	BITMUL_Circuit_2I(garbledCircuit, garblingContext, split, inputA, a_les_b, min_case_1);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, split, inputB, a_geq_b, min_case_2);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, n, XOR, min_case_1, min_case_2, outputs);

	BITMUL_Circuit_2I(garbledCircuit, garblingContext, split, inputB, a_les_b, max_case_1);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, split, inputA, a_geq_b, max_case_2);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, n, XOR, max_case_1, max_case_2, &outputs[split]);
}



//computes multiplication of n-bit value a by bit value b

int BITMUL_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* input_A, int input_B, int* outputs)
{
	for (int i = 0; i < n; i++)
	{
		MIXED_OP_Gate(garbledCircuit, garblingContext, AND, input_A[i], input_B, &outputs[i]);
	}
}



// Int_Representation_ in {SIGNED, UNSIGNED}
// avoids using sign extension to minimize gate count
// for unsigned ints, this is natural multiplication
// for signed ints, uses Baugh-Wooley representation
// automatically calls optimized squaring routine on matching inputs

int MUL_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int *inputs, int *outputs)
{
	MUL_Circuit_2I(garbledCircuit, garblingContext, n, inputs, &inputs[n/2], outputs);
}


int MUL_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int *inputA, int *inputB, int *outputs)
{
	int split = n / 2;

	if (inputA == inputB)
	{
		int stopping_split = split >> (1 + (lg_flr(split) >> 1));
		SQUARE_2R_G_Circuit(garbledCircuit, garblingContext, n, inputA, outputs, stopping_split);

		return 0;
	}

	int inputA_copy[split];
	int inputB_copy[split];
	memcpy(inputA_copy, inputA, split * sizeof(int));
	memcpy(inputB_copy, inputB, split * sizeof(int));

	int out_conj[split][split + Int_Representation_];	//Int_Representation_ == SIGNED ? 1 : 0

	for (int i = 0; i < split; i++)
		BITMUL_Circuit_2I(garbledCircuit, garblingContext, split, inputA_copy, inputB_copy[i], (int*) &out_conj[i]);

	int in_add[2 * (split + Int_Representation_)];
	int out_add[2 * (split + Int_Representation_)];

	if (Int_Representation_ == SIGNED) {	//use Baugh-Wooley optimization to avoid sign extension

		for (int i = 0; i < split - 1; i++) {
			NOT_Gate2(garbledCircuit, garblingContext, out_conj[i][split-1], &out_conj[i][split-1]);
			if ((i != 0) && (i != split-1))
				out_conj[i][split] = fixedZeroWire(garbledCircuit, garblingContext);
			NOT_Gate2(garbledCircuit, garblingContext, out_conj[split-1][i], &out_conj[split-1][i]);
		}
		out_conj[0][split] = fixedOneWire(garbledCircuit, garblingContext);
		out_conj[split-1][split] = fixedOneWire(garbledCircuit, garblingContext);
	}

	for (int i = 0; i < split + Int_Representation_; i++) {
		out_add[i] = out_conj[0][i];
		out_add[i + split + Int_Representation_] = fixedZeroWire(garbledCircuit, garblingContext);
	}

	for (int i = 1; i < split; i++) {
		for (int j = 0; j < split + Int_Representation_; j++) {
			in_add[j] = out_add[j + i];
			in_add[j + split + Int_Representation_] = out_conj[i][j];
		}
		ADD_Circuit2(garbledCircuit, garblingContext, 2 * (split + Int_Representation_), OVERFLOW, in_add, out_add + i);
	}

	memcpy(outputs, out_add, n * sizeof(int));
}



int DOTPROD_Circuit2(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int num_inputs, int input_length, int *inputs, int *outputs)
{
	int split = num_inputs * input_length;
	DOTPROD_Circuit_2I(garbledCircuit, garblingContext, num_inputs, input_length, inputs, &inputs[split], outputs);
}


// automatically calls optimized squaring routine on matching inputs

int DOTPROD_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int num_inputs, int input_length, int *inputA, int *inputB, int *outputs)
{

	int split = num_inputs * input_length;
	int inputA_copy[split];
	int inputB_copy[split];
	memcpy(inputA_copy, inputA, split * sizeof(int));
	memcpy(inputB_copy, inputB, split * sizeof(int));

	int output_length = 2 * input_length + lg_flr(num_inputs);
	int out_mul[num_inputs][output_length];

	int zero = 0;
	SETCONST_Circuit(garbledCircuit, garblingContext, output_length, &zero, outputs);

	for (int i = 0; i < num_inputs; i++)
	{
		SETCONST_Circuit(garbledCircuit, garblingContext, lg_flr(num_inputs), &zero, &out_mul[i][2 * input_length]);
		if (inputA == inputB)
		{
			int stopping_split = input_length >> (1 + (lg_flr(input_length) >> 1));
			SQUARE_2R_G_Circuit(garbledCircuit, garblingContext, 2 * input_length, &inputA_copy[i * input_length], (int *) &out_mul[i], stopping_split);
		}
		else
			MUL_Circuit_2I(garbledCircuit, garblingContext, 2 * input_length, &inputA_copy[i * input_length], &inputB_copy[i * input_length], (int *) &out_mul[i]);
	}

	SUM_Circuit(garbledCircuit, garblingContext, num_inputs, 2 * input_length, (int *) out_mul, outputs);
}


//computes the square of the value stored in *inputs using recursive approach similar to Karatsuba multiplication on (x,x)
//but using standard multiplication for the middle term
//better for small input sizes

//expects value to be squared to reside in inputs[0..split-1], output in outputs[0..2*split-1]
//can handle arbitrary input lengths, and allows for adjustable recursion stopping condition
//for input sizes of concern, sqrt(input) is usually near optimal choice for stopping_split
//for 8-bit through 32-bit inputs, stopping_split == 4 is optimal

int SQUARE_2R_G_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs, int stopping_split)
{
	int split = n / 2;
	int internal_split = (split / 2) + (split % 2);

	int input_copy[split];
	memcpy(input_copy, inputs, split * sizeof(int));

	int *in_mult_lo = (int*) malloc(sizeof(int) * 2 * internal_split);
	int *in_mult_mid = (int*) malloc(sizeof(int) * 2 * internal_split);
	int *in_mult_hi = (int*) malloc(sizeof(int) * 2 * internal_split);

	int *out_mult_lo = (int*) malloc(sizeof(int) * 2 * internal_split);
	int *out_mult_mid = (int*) malloc(sizeof(int) * 2 * internal_split);
	int *out_mult_hi = (int*) malloc(sizeof(int) * 2 * internal_split);

	int *in_add = (int*) malloc(sizeof(int) * 8 * internal_split);
	int *out_add = (int*) malloc(sizeof(int) * 4 * internal_split);

	for (int i = 0; i < internal_split; i++) {
		in_mult_lo[i] = input_copy[i];
		in_mult_lo[i + internal_split] = input_copy[i];
		in_mult_mid[i] = input_copy[i];
		in_mult_mid[i + internal_split] = input_copy[i + internal_split];
		in_mult_hi[i] = input_copy[i + internal_split];
		in_mult_hi[i + internal_split] = input_copy[i + internal_split];
	}

	int end_of_recursion = (split <= stopping_split) || (split % 2  != 0);

	if (end_of_recursion) {
		MUL_Circuit2(garbledCircuit, garblingContext, 2 * internal_split, in_mult_lo, out_mult_lo);
		MUL_Circuit2(garbledCircuit, garblingContext, 2 * internal_split, in_mult_hi, out_mult_hi);
	}
	else {
		SQUARE_2R_G_Circuit(garbledCircuit, garblingContext, 2 * internal_split, in_mult_lo, out_mult_lo, stopping_split);
		SQUARE_2R_G_Circuit(garbledCircuit, garblingContext, 2 * internal_split, in_mult_hi, out_mult_hi, stopping_split);
	}

	MUL_Circuit2(garbledCircuit, garblingContext, 2 * internal_split, in_mult_mid, out_mult_mid);

	for (int i = 0; i < internal_split; i++) {
		in_add[i + (4 * internal_split)] = fixedZeroWire(garbledCircuit, garblingContext);
		if (i > 0)
			in_add[i + (7 * internal_split)] = fixedZeroWire(garbledCircuit, garblingContext);
	}
	in_add[5 * internal_split] = fixedZeroWire(garbledCircuit, garblingContext);

	for (int i = 0; i < 2 * internal_split; i++) {
		in_add[i] = out_mult_lo[i];
		in_add[i + (2 * internal_split)] = out_mult_hi[i];
		in_add[i + (5 * internal_split)  + 1] = out_mult_mid[i];
	}

	ADD_Circuit2(garbledCircuit, garblingContext, 8 * internal_split, NO_OVERFLOW, in_add, out_add);

	for (int i = 0; i < n; i++) {
		outputs[i] = out_add[i];
	}

	free(in_mult_lo);	free(in_mult_mid);	free(in_mult_hi);
	free(out_mult_lo);	free(out_mult_mid);	free(out_mult_hi);
	free(in_add);	free(out_add);

}




//computes Karatsuba multiplication on two inputs packed into *inputs, stopping recursion by the time input size reaches stopping_split
//only more efficient when input length is sufficiently large

int KMUL_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs, int stopping_split)
{
	int split = n / 2;
	int internal_split = (split / 2) + (split % 2);

	int input_copy[n];
	memcpy(input_copy, inputs, n * sizeof(int));

	int *in_mult_lo = (int*) malloc(sizeof(int) * 2 *  internal_split);
	int *in_mult_mid = (int*) malloc(sizeof(int) * 2 *  (internal_split + 1));
	int *in_mult_hi = (int*) malloc(sizeof(int) * 2 * internal_split);

	int *add_mid_x = (int*) malloc(sizeof(int) * 2 * internal_split);
	int *add_mid_y = (int*) malloc(sizeof(int) * 2 * internal_split);

	int *out_mult_lo = (int*) malloc(sizeof(int) * 2 * internal_split);
	int *out_mult_mid = (int*) malloc(sizeof(int) * 2 * (internal_split + 1));
	int *out_mult_hi = (int*) malloc(sizeof(int) * 2 * internal_split);

	int *in_sub = (int*) malloc(sizeof(int) * 4 * (internal_split + 1));
	int *in_hilo_sum = (int*) malloc(sizeof(int) * 4 * internal_split);
	int *out_hilo_sum = (int*) malloc(sizeof(int) * 2 * internal_split + 1);
	int *out_sub = (int*) malloc(sizeof(int) * 2 * (internal_split + 1));

	int *in_add = (int*) malloc(sizeof(int) * 8 * internal_split);
	int *out_add = (int*) malloc(sizeof(int) * 4 * internal_split);

	for (int i = 0; i < internal_split; i++) {
		in_mult_lo[i] = input_copy[i];
		in_mult_lo[i + internal_split] = input_copy[i + split];
		if (i + internal_split < split) {
			in_mult_hi[i] = input_copy[i + internal_split];
			in_mult_hi[i + internal_split] = input_copy[i + split + internal_split];
		}
		else {
			in_mult_hi[i] = fixedZeroWire(garbledCircuit, garblingContext);
			in_mult_hi[i + internal_split] = fixedZeroWire(garbledCircuit, garblingContext);
		}
	}

	for (int i = 0; i < internal_split; i++) {
		add_mid_x[i] = in_mult_lo[i];
		add_mid_x[i + internal_split] = in_mult_hi[i];
		add_mid_y[i] = in_mult_lo[i + internal_split];
		add_mid_y[i + internal_split] = in_mult_hi[i + internal_split];
	}

	ADD_Circuit2(garbledCircuit, garblingContext, 2 * internal_split, OVERFLOW, add_mid_x, in_mult_mid);
	ADD_Circuit2(garbledCircuit, garblingContext, 2 * internal_split, OVERFLOW, add_mid_y, in_mult_mid + internal_split + 1);

	//int end_of_recursion = (split <= stopping_split);
	int end_of_recursion = (split <= stopping_split) || (split % 2  != 0);

	if (end_of_recursion) {
		MUL_Circuit2(garbledCircuit, garblingContext, 2 * internal_split, in_mult_lo, out_mult_lo);
		MUL_Circuit2(garbledCircuit, garblingContext, 2 * internal_split, in_mult_hi, out_mult_hi);
		MUL_Circuit2(garbledCircuit, garblingContext, 2 * (internal_split + 1), in_mult_mid, out_mult_mid);
	}
	else {
		KMUL_Circuit(garbledCircuit, garblingContext, 2 * internal_split, in_mult_lo, out_mult_lo, stopping_split);
		KMUL_Circuit(garbledCircuit, garblingContext, 2 * internal_split, in_mult_hi, out_mult_hi, stopping_split);
		KMUL_Circuit(garbledCircuit, garblingContext, 2 * (internal_split + 1), in_mult_mid, out_mult_mid, stopping_split);
	}

	for (int i = 0; i < 2 * internal_split; i++) {
		in_hilo_sum[i] = out_mult_lo[i];
		in_hilo_sum[i + (2 * internal_split)] = out_mult_hi[i];
	}

	ADD_Circuit2(garbledCircuit, garblingContext, 4 * internal_split, OVERFLOW, in_hilo_sum, out_hilo_sum);

	for (int i = 0; i < 2 * (internal_split + 1); i++) {
		in_sub[i] = out_mult_mid[i];
		if (i < 2 * internal_split + 1)
			in_sub[i + 2*(internal_split + 1)] = out_hilo_sum[i];
		else
			in_sub[i + 2*(internal_split + 1)] = fixedZeroWire(garbledCircuit, garblingContext);
	}

	SUB_Circuit2(garbledCircuit, garblingContext, 4 * (internal_split + 1), NO_UNDERFLOW, in_sub, out_sub);

	for (int i = 0; i < 2 * (internal_split + 1); i++) {
		if (i < 2 * internal_split) {
			in_add[i] = out_mult_lo[i];
			in_add[i + 2*internal_split] = out_mult_hi[i];
		}
		in_add[i + 5*internal_split] = out_sub[i];
		if (i < internal_split)
			in_add[i + 4*internal_split] = fixedZeroWire(garbledCircuit, garblingContext);
		else if (i > internal_split + 2)
			in_add[i + 6*internal_split] = fixedZeroWire(garbledCircuit, garblingContext);
	}

	ADD_Circuit2(garbledCircuit, garblingContext, 8 * internal_split, NO_OVERFLOW, in_add, out_add);

	for (int i = 0; i < n; i++) {
		outputs[i] = out_add[i];
	}

	free(in_mult_lo);	free(in_mult_mid);	free(in_mult_hi);
	free(add_mid_x);	free(add_mid_y);
	free(out_mult_lo);	free(out_mult_mid);	free(out_mult_hi);
	free(in_sub);	free(in_hilo_sum);	free(out_hilo_sum);	free(out_sub);
	free(in_add);	free(out_add);
}





////////////////////////////////////////////////////////////////////////////////
/////////	Floating point functions

//NOTE uses IEEE 754 - 32 bits: 23 value (mantissa) bits, one sign bit, 8 exponent bits
//NOTE additionally stores three bit flags which for use in processing zero, subnormal, and special numbers
//NOTE EXP_ZERO_FLAG == 1 iff the exponent is zero
//NOTE EXP_SPEC_FLAG == 1 iff the exponent is -1
//NOTE MANT_ZERO_FLAG == 1 iff the mantissa is zero

#define RAW_MANTISSA 0
#define RAW_EXPONENT 23
#define RAW_SIGN 31



// function to add or remove the bias on the (unsigned int) exponent after operations on the exponent

int FLOAT_EXP_BIAS_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int bias_task, int* inputs, int* outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	memcpy(outputs, inputs, SINGLE_LENGTH * sizeof(int));

	int bias = bias_task == ADD ? 127 : -127;
	int bias_bits[8];

	SETCONST_Circuit(garbledCircuit, garblingContext, 8, &bias, bias_bits);
	ADD_Circuit_2I(garbledCircuit, garblingContext, 16, NO_OVERFLOW, bias_bits, &inputs[EXPONENT], &outputs[EXPONENT]);

	Int_Representation_ = old_int_rep;
}



int SET_RAW_FLOAT_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int* inputs, int* outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	int zero_bits[23];
	int mask_bits[8];

	memcpy(&outputs[MANTISSA], &inputs[RAW_MANTISSA], 23 * sizeof(int));
	memcpy(&outputs[EXPONENT], &inputs[RAW_EXPONENT], 8 * sizeof(int));
	memcpy(&outputs[SIGN], &inputs[RAW_SIGN], 1 * sizeof(int));

	SETCONST_Circuit(garbledCircuit, garblingContext, 23, &zero, zero_bits);
	SETCONST_Circuit(garbledCircuit, garblingContext, 8, &mask, mask_bits);

	CMP_Circuit_2I(garbledCircuit, garblingContext, 46, EQ, &inputs[RAW_MANTISSA], zero_bits, &outputs[MANT_ZERO_FLAG]);
	CMP_Circuit_2I(garbledCircuit, garblingContext, 16, EQ, &inputs[RAW_EXPONENT], zero_bits, &outputs[EXP_ZERO_FLAG]);
	CMP_Circuit_2I(garbledCircuit, garblingContext, 16, EQ, &inputs[RAW_EXPONENT], mask_bits, &outputs[EXP_SPEC_FLAG]);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, outputs[EXP_ZERO_FLAG], outputs[MANT_ZERO_FLAG], &outputs[ZERO_FLAG]);

	Int_Representation_ = old_int_rep;
}



int SET_CONST_FLOAT_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int mantissa, int exponent, int sign, int* outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	SETCONST_Circuit(garbledCircuit, garblingContext, 23, &mantissa, &outputs[MANTISSA]);
	SETCONST_Circuit(garbledCircuit, garblingContext, 8, &exponent, &outputs[EXPONENT]);
	SETCONST_Circuit(garbledCircuit, garblingContext, 1, &sign, &outputs[SIGN]);

	outputs[EXP_ZERO_FLAG] = exponent == 0 ? fixedOneWire(garbledCircuit, garblingContext) : fixedZeroWire(garbledCircuit, garblingContext);
	outputs[EXP_SPEC_FLAG] = exponent == -1 ? fixedOneWire(garbledCircuit, garblingContext) : fixedZeroWire(garbledCircuit, garblingContext);
	outputs[MANT_ZERO_FLAG] = mantissa == 0 ? fixedOneWire(garbledCircuit, garblingContext) : fixedZeroWire(garbledCircuit, garblingContext);
	outputs[ZERO_FLAG] = ((mantissa == 0) && (exponent == 0)) ? fixedOneWire(garbledCircuit, garblingContext) : fixedZeroWire(garbledCircuit, garblingContext);

	Int_Representation_ = old_int_rep;
}



int SET_CONST_FLOAT_CAST_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, float const_input, int* outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	int sign = const_input < 0 ? 1 : 0;

	int mant_mask = (1 << 23) - 1;
	int exp_mask = ((1 << 30) - 1) ^ mant_mask;
	int sign_mask = 1 << 31;

	int mantissa = (int) ((float) const_input) & mant_mask;
	int exponent = (int) ((float) const_input) & exp_mask;

	SETCONST_Circuit(garbledCircuit, garblingContext, 23, &mantissa, &outputs[MANTISSA]);
	SETCONST_Circuit(garbledCircuit, garblingContext, 8, &exponent, &outputs[EXPONENT]);
	SETCONST_Circuit(garbledCircuit, garblingContext, 1, &sign, &outputs[SIGN]);

	outputs[EXP_ZERO_FLAG] = exponent == 0 ? fixedOneWire(garbledCircuit, garblingContext) : fixedZeroWire(garbledCircuit, garblingContext);
	outputs[EXP_SPEC_FLAG] = exponent == -1 ? fixedOneWire(garbledCircuit, garblingContext) : fixedZeroWire(garbledCircuit, garblingContext);
	outputs[MANT_ZERO_FLAG] = mantissa == 0 ? fixedOneWire(garbledCircuit, garblingContext) : fixedZeroWire(garbledCircuit, garblingContext);
	outputs[ZERO_FLAG] = const_input == 0 ? fixedOneWire(garbledCircuit, garblingContext) : fixedZeroWire(garbledCircuit, garblingContext);

	Int_Representation_ = old_int_rep;
}



int INT_TO_FLOAT_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	if (n > 128)
	{
		//NaN
		SET_CONST_FLOAT_Circuit(garbledCircuit, garblingContext, one, mask, zero, outputs);

		Int_Representation_ = old_int_rep;
		return -1;
	}

	int k = n < 23 ? n : 23;
	int l = 1 + lg_flr(k - 1);
	int nonzero_mant;

	int msb_mask[23];
	int shifted_input[23];
	memcpy(shifted_input, &inputs[n-k], k * sizeof(int));

	if (k < 23)
	{
		SETCONST_Circuit(garbledCircuit, garblingContext, 23 - k, &zero, &shifted_input[k]);
		SETCONST_Circuit(garbledCircuit, garblingContext, 23 - k, &zero, &msb_mask[k]);
	}

	int oblv_msb_index[8];

	MSB_Circuit(garbledCircuit, garblingContext, k, MASK_AND_INDEX, shifted_input, msb_mask, oblv_msb_index, &nonzero_mant);
	SETCONST_Circuit(garbledCircuit, garblingContext, 8 - l, &zero, &oblv_msb_index[l]);
	memcpy(&outputs[EXPONENT], oblv_msb_index, 8 * sizeof(int));

	if (n > k)
	{
		int exp_offset = n - k;
		int exp_offset_bits[8];
		SETCONST_Circuit(garbledCircuit, garblingContext, 8, &exp_offset, exp_offset_bits);
		ADD_Circuit_2I(garbledCircuit, garblingContext, 16, NO_OVERFLOW, exp_offset_bits, &outputs[EXPONENT], &outputs[EXPONENT]);
	}

	if (k < 23)
		SHIFT_Circuit(garbledCircuit, garblingContext, 23, 23 - k, LEFT, TRUNC, POSITIVE, shifted_input, shifted_input);

	if (Int_Representation_ == SIGNED)
	{
		outputs[SIGN] = inputs[n-1];
		int negative_input[23];
		int pos_sgnd_int;
		int neg_sgnd_int = outputs[SIGN];
		NOT_Gate2(garbledCircuit, garblingContext, neg_sgnd_int, &pos_sgnd_int);
		NEG_Circuit(garbledCircuit, garblingContext, 23, shifted_input, negative_input);
		BITMUL_Circuit_2I(garbledCircuit, garblingContext, 23, shifted_input, pos_sgnd_int, shifted_input);
		BITMUL_Circuit_2I(garbledCircuit, garblingContext, 23, negative_input, neg_sgnd_int, negative_input);
		MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 46, XOR, shifted_input, negative_input, shifted_input);
	}
	else
		outputs[SIGN] = fixedZeroWire(garbledCircuit, garblingContext);

	int shift_offset_bits[8];
	int shift_offset = k + 1;

	SETCONST_Circuit(garbledCircuit, garblingContext, l, &shift_offset, shift_offset_bits);
	SETCONST_Circuit(garbledCircuit, garblingContext, 8 - l, &zero, &shift_offset_bits[l]);
	SUB_Circuit_2I(garbledCircuit, garblingContext, 2*l, NO_UNDERFLOW, shift_offset_bits, oblv_msb_index, shift_offset_bits);
	OBLV_SHIFT_Circuit(garbledCircuit, garblingContext, 23, LEFT, TRUNC, POSITIVE, k + 1, shift_offset_bits, shifted_input, &outputs[MANTISSA]);

	FLOAT_EXP_BIAS_Circuit(garbledCircuit, garblingContext, ADD, outputs, outputs);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, 8, &outputs[EXPONENT], nonzero_mant, &outputs[EXPONENT]);

	NOT_Gate2(garbledCircuit, garblingContext, nonzero_mant, &outputs[MANT_ZERO_FLAG]);
	outputs[EXP_ZERO_FLAG] = outputs[MANT_ZERO_FLAG];
	outputs[EXP_SPEC_FLAG] = fixedZeroWire(garbledCircuit, garblingContext);
	outputs[ZERO_FLAG] = outputs[MANT_ZERO_FLAG];

	Int_Representation_ = old_int_rep;
}




// function to normalize floating point value after additions or multiplications on the mantissa of an already normalized value
// returns the IEEE representatin of zero if additions or multiplications on the mantissa produce zero, and the input value otherwise
//CAUTION this function should only be called after a primitive operation between mantissas of two inputs
//CAUTION calling this function on an already checked vector can corrupt the value
//CAUTION EXP_SPEC_FLAG is passed through and should be set in *CHECK_SPECIAL()

int FLOAT_CHECK_ZERO_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int* inputs, int* outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	memcpy(outputs, inputs, SINGLE_LENGTH * sizeof(int));

	int zero_bits[23];
	int nonzero_mant;

	SETCONST_Circuit(garbledCircuit, garblingContext, 23, &zero, zero_bits);
	CMP_Circuit_2I(garbledCircuit, garblingContext, 46, NEQ, &inputs[MANTISSA], zero_bits, &nonzero_mant);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, 8, &inputs[EXPONENT], nonzero_mant, &outputs[EXPONENT]);

	NOT_Gate2(garbledCircuit, garblingContext, nonzero_mant, &outputs[MANT_ZERO_FLAG]);
	outputs[EXP_ZERO_FLAG] = outputs[MANT_ZERO_FLAG];
	outputs[EXP_SPEC_FLAG] = inputs[EXP_SPEC_FLAG];
	outputs[ZERO_FLAG] = outputs[EXP_ZERO_FLAG];

	Int_Representation_ = old_int_rep;
}



//NOTE FLOAT_CHECK_SPECIAL_Circuit and FLOAT_CHECK_SPECIAL_BATCH_Circuit are intended to be called as an internal subroutine of primitive float operation circuits
//NOTE this function fills outputs with a zero float if neither input is special and different special values depending on the given parameters
//NOTE the return value is a wire which represents 1 if and only if both inputs are normal
//NOTE it is presumed that that wire will be ANDed with the normal operation output and that result XORed with the values in outputs

int FLOAT_CHECK_SPECIAL_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int op_type, int ininity_type, int* inputA, int* inputB, int* outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	int inputA_copy[SINGLE_LENGTH];
	int inputB_copy[SINGLE_LENGTH];
	memcpy(inputA_copy, inputA, SINGLE_LENGTH * sizeof(int));
	memcpy(inputB_copy, inputB, SINGLE_LENGTH * sizeof(int));

	int at_least_one_special_input;
	int neither_input_special;

	int float_zero[SINGLE_LENGTH];
	int fixed_nan[SINGLE_LENGTH];
	SET_CONST_FLOAT_Circuit(garbledCircuit, garblingContext, one, mask, zero, fixed_nan);
	SET_CONST_FLOAT_Circuit(garbledCircuit, garblingContext, zero, zero, zero, float_zero);

	if (ininity_type == INFTY_EQ_NAN)
	{
		int special_case[SINGLE_LENGTH];
		int normal_case[SINGLE_LENGTH];

		MIXED_OP_Gate(garbledCircuit, garblingContext, OR, inputA_copy[EXP_SPEC_FLAG], inputB_copy[EXP_SPEC_FLAG], &at_least_one_special_input);
		NOT_Gate2(garbledCircuit, garblingContext, at_least_one_special_input, &neither_input_special);
		BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, fixed_nan, at_least_one_special_input, special_case);
		BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, float_zero, neither_input_special, normal_case);
		MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * SINGLE_LENGTH, XOR, special_case, normal_case, outputs);

		return neither_input_special;
	}
	else
	{
		int both_inputs_special;
		int one_input_special;
		int both_mants_zero;
		int one_mant_zero;
		int at_least_one_mant_special;
		int neither_mant_zero;
		int same_sign;
		int different_sign;

		MIXED_OP_Gate(garbledCircuit, garblingContext, AND, inputA_copy[EXP_SPEC_FLAG], inputB_copy[EXP_SPEC_FLAG], &both_inputs_special);
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[EXP_SPEC_FLAG], inputB_copy[EXP_SPEC_FLAG], &one_input_special);
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, both_inputs_special, one_input_special, &at_least_one_special_input);
		NOT_Gate2(garbledCircuit, garblingContext, at_least_one_special_input, &neither_input_special);
		MIXED_OP_Gate(garbledCircuit, garblingContext, AND, inputA_copy[MANT_ZERO_FLAG], inputB_copy[MANT_ZERO_FLAG], &both_mants_zero);
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[MANT_ZERO_FLAG], inputB_copy[MANT_ZERO_FLAG], &one_mant_zero);
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, both_mants_zero, one_mant_zero, &at_least_one_mant_special);
		NOT_Gate2(garbledCircuit, garblingContext, at_least_one_mant_special, &neither_mant_zero);
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[SIGN], inputB_copy[SIGN], &same_sign);
		NOT_Gate2(garbledCircuit, garblingContext, same_sign, &different_sign);

		//TODO finish
	}
	Int_Representation_ = old_int_rep;
}



int FLOAT_CHECK_SPECIAL_BATCH_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int op_type, int ininity_type, int num_inputs, int input_length, int* inputs, int* outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	int input_copy[num_inputs * input_length];
	memcpy(input_copy, inputs, num_inputs * input_length * sizeof(int));

	int at_least_one_special_input = input_copy[EXP_SPEC_FLAG];
	int neither_input_special;

	int float_zero[SINGLE_LENGTH];
	int fixed_nan[SINGLE_LENGTH];
	SET_CONST_FLOAT_Circuit(garbledCircuit, garblingContext, one, mask, zero, fixed_nan);
	SET_CONST_FLOAT_Circuit(garbledCircuit, garblingContext, zero, zero, zero, float_zero);

	if (ininity_type == INFTY_EQ_NAN)
	{
		int special_case[SINGLE_LENGTH];
		int normal_case[SINGLE_LENGTH];

		for (int i = 1; i < num_inputs; i++)
			MIXED_OP_Gate(garbledCircuit, garblingContext, OR, at_least_one_special_input, input_copy[i*input_length + EXP_SPEC_FLAG], &at_least_one_special_input);

		NOT_Gate2(garbledCircuit, garblingContext, at_least_one_special_input, &neither_input_special);
		BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, fixed_nan, at_least_one_special_input, special_case);
		BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, float_zero, neither_input_special, normal_case);
		MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * SINGLE_LENGTH, XOR, special_case, normal_case, outputs);

		return neither_input_special;
	}
	else
	{
		int both_inputs_special;
		int one_input_special;
		int both_mants_zero;
		int one_mant_zero;
		int at_least_one_mant_special;
		int neither_mant_zero;
		int same_sign;
		int different_sign;

		/*
		 *	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, inputA[EXP_SPEC_FLAG], inputB[EXP_SPEC_FLAG], &both_inputs_special);
		 *	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA[EXP_SPEC_FLAG], inputB[EXP_SPEC_FLAG], &one_input_special);
		 *	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, both_inputs_special, one_input_special, &at_least_one_special_input);
		 *	NOT_Gate2(garbledCircuit, garblingContext, at_least_one_special_input, &neither_input_special);
		 *	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, inputA[MANT_ZERO_FLAG], inputB[MANT_ZERO_FLAG], &both_mants_zero);
		 *	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA[MANT_ZERO_FLAG], inputB[MANT_ZERO_FLAG], &one_mant_zero);
		 *	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, both_mants_zero, one_mant_zero, &at_least_one_mant_special);
		 *	NOT_Gate2(garbledCircuit, garblingContext, at_least_one_mant_special, &neither_mant_zero);
		 *	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA[SIGN], inputB[SIGN], &same_sign);
		 *	NOT_Gate2(garbledCircuit, garblingContext, same_sign, &different_sign);
		 */

		//TODO adjust the above (using input_copy) and finish
	}
	Int_Representation_ = old_int_rep;
}



// function to add a vector of floats without normalizing between each addition
// generalizes floating point representation to an arbitrary length mantissa
//CAUTION this function is a helper function for FLOAT_SUM and does *not* provide output in 32 bit signle precision form

#define VAR_MANTISSA (MANTISSA)
#define VAR_MANT_ZERO_FLAG (MANT_ZERO_FLAG + num_overflow_bits)
#define VAR_EXPONENT (EXPONENT + num_overflow_bits)
#define VAR_EXP_ZERO_FLAG (EXP_ZERO_FLAG + num_overflow_bits)
#define VAR_EXP_SPEC_FLAG (EXP_SPEC_FLAG + num_overflow_bits)
#define VAR_ZERO_FLAG (ZERO_FLAG + num_overflow_bits)
#define VAR_SIGN (SIGN + num_overflow_bits)
#define VAR_SINGLE_LENGTH (SINGLE_LENGTH + num_overflow_bits)

int FLOAT_ADD_RAW_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int num_overflow_bits, int *inputA, int *inputB, int *outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	int inputA_copy[VAR_SINGLE_LENGTH];
	int inputB_copy[VAR_SINGLE_LENGTH];
	memcpy(inputA_copy, inputA, VAR_SINGLE_LENGTH * sizeof(int));
	memcpy(inputB_copy, inputB, VAR_SINGLE_LENGTH * sizeof(int));

	int max_shift = 24 + num_overflow_bits;

	int mantA[max_shift];
	int mantB[max_shift];
	memcpy(mantA, &inputA[VAR_MANTISSA], max_shift * sizeof(int));
	memcpy(mantB, &inputB[VAR_MANTISSA], max_shift * sizeof(int));

	int max_shift_bits[8];
	int expA_minus_expB[8];
	int expB_minus_expA[8];
	int expA_geq_expB[2];
	int expA_les_expB;
	int overshift_A[2];
	int overshift_B[2];

	SETCONST_Circuit(garbledCircuit, garblingContext, 8, &max_shift, max_shift_bits);

	SUB_Circuit_2I(garbledCircuit, garblingContext, 16, NO_UNDERFLOW, &inputA_copy[VAR_EXPONENT], &inputB_copy[VAR_EXPONENT], expA_minus_expB);
	NEG_Circuit(garbledCircuit, garblingContext, 8, expA_minus_expB, expB_minus_expA);
	CMP_Circuit_2I(garbledCircuit, garblingContext, 16, GEQ, expA_minus_expB, max_shift_bits, overshift_A);
	CMP_Circuit_2I(garbledCircuit, garblingContext, 16, GEQ, expB_minus_expA, max_shift_bits, overshift_B);

	CMP_Circuit_2I(garbledCircuit, garblingContext, 16, GEQ, &inputA_copy[VAR_EXPONENT], &inputB_copy[VAR_EXPONENT], expA_geq_expB);
	NOT_Gate2(garbledCircuit, garblingContext, expA_geq_expB[0], &expA_les_expB);

	int mixed_sign;
	int same_sign;

	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[VAR_SIGN], inputB_copy[VAR_SIGN], &mixed_sign);
	NOT_Gate2(garbledCircuit, garblingContext, mixed_sign, &same_sign);

	int shr_mantA[max_shift];
	int shr_mantB[max_shift];
	int mantA_plus_shrmantB[max_shift];
	int mantB_plus_shrmantA[max_shift];
	int mantA_minus_shrmantB[max_shift];
	int mantB_minus_shrmantA[max_shift];

	memcpy(shr_mantA, mantA, max_shift * sizeof(int));
	memcpy(shr_mantB, mantB, max_shift * sizeof(int));

	int test_case_1[max_shift];
	int test_case_2[max_shift];
	int test_condition_1;
	int test_condition_2;
	int test_condition_3;
	int test_condition_4;
	int mantA_grt_mantB[2];
	int mantA_leq_mantB;
	int candidate_mantissa[max_shift];
	int candidate_sign;

	BITMUL_Circuit_2I(garbledCircuit, garblingContext, 8, expA_minus_expB, expA_geq_expB[0], test_case_1);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, 8, expB_minus_expA, expA_les_expB, test_case_2);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 16, XOR, test_case_1, test_case_2, &outputs[VAR_EXPONENT]);

	OBLV_SHIFT_Circuit(garbledCircuit, garblingContext, max_shift, RIGHT, TRUNC, POSITIVE, max_shift - 1, expA_minus_expB, shr_mantB, shr_mantB);
	OBLV_SHIFT_Circuit(garbledCircuit, garblingContext, max_shift, RIGHT, TRUNC, POSITIVE, max_shift - 1, expB_minus_expA, shr_mantA, shr_mantA);

	ADD_Circuit_2I(garbledCircuit, garblingContext, 2 * max_shift, NO_OVERFLOW, mantA, shr_mantB, mantA_plus_shrmantB);
	ADD_Circuit_2I(garbledCircuit, garblingContext, 2 * max_shift, NO_OVERFLOW, shr_mantA, mantB, mantB_plus_shrmantA);
	SUB_Circuit_2I(garbledCircuit, garblingContext, 2 * max_shift, NO_UNDERFLOW, mantA, shr_mantB, mantA_minus_shrmantB);
	SUB_Circuit_2I(garbledCircuit, garblingContext, 2 * max_shift, NO_UNDERFLOW, mantB, shr_mantA, mantB_minus_shrmantA);

	//case: overshift

	BITMUL_Circuit_2I(garbledCircuit, garblingContext, max_shift, mantA, overshift_A[0], test_case_1);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, max_shift, mantB, overshift_B[0], test_case_2);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * max_shift, XOR, test_case_1, test_case_2, candidate_mantissa);

	//case: same sign

	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, expA_geq_expB[0], same_sign, &test_condition_1);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, expA_les_expB, same_sign, &test_condition_2);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, max_shift, mantA_plus_shrmantB, test_condition_1, test_case_1);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, max_shift, mantB_plus_shrmantA, test_condition_2, test_case_2);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * max_shift, XOR, test_case_1, test_case_2, test_case_1);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * max_shift, XOR, test_case_1, candidate_mantissa, candidate_mantissa);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, inputB[VAR_SIGN], same_sign, &outputs[VAR_SIGN]);

	//case: mixed sign

	//NOTE computing mantA_grt_mantB is only relevant when expA == expB, but must be considered for the expA >= expB case
	//NOTE and is used to compute the output sign
	CMP_Circuit_2I(garbledCircuit, garblingContext, 2 * max_shift, GRT, mantA, mantB, mantA_grt_mantB);
	NOT_Gate2(garbledCircuit, garblingContext, expA_geq_expB[0], &mantA_leq_mantB);

	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputB[VAR_SIGN], mantA_grt_mantB[0], &candidate_sign);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, candidate_sign, mixed_sign, &candidate_sign);
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, candidate_sign, outputs[VAR_SIGN], &outputs[VAR_SIGN]);

	//mixed sign subcase: exp A >= exp B

	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, expA_geq_expB[0], mixed_sign, &test_condition_1);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, test_condition_1, mantA_grt_mantB[0], &test_condition_3);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, test_condition_1, mantA_leq_mantB, &test_condition_4);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, max_shift, mantA_minus_shrmantB, test_condition_3, test_case_1);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, max_shift, mantB_minus_shrmantA, test_condition_4, test_case_2);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * max_shift, XOR, test_case_1, test_case_2, test_case_1);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * max_shift, XOR, candidate_mantissa, test_case_1, candidate_mantissa);

	//mixed sign subcase: expB > exp A

	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, expA_les_expB, mixed_sign, &test_condition_2);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, max_shift, mantB_minus_shrmantA, test_condition_2, test_case_2);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * max_shift, XOR, candidate_mantissa, test_case_2, candidate_mantissa);

	memcpy(&outputs[VAR_MANTISSA], candidate_mantissa, max_shift * sizeof(int));
	//NOTE VAR_*_ZERO_FLAGs will be set after the call to FLOAT_CHECK_ZERO() and the following values are placeholders
	//NOTE meanwhile, VAR_EXP_SPEC_FLAG = 0 for assumed normal outputs
	outputs[VAR_EXP_ZERO_FLAG] = inputA_copy[VAR_EXP_ZERO_FLAG];
	outputs[VAR_MANT_ZERO_FLAG] = inputA_copy[VAR_MANT_ZERO_FLAG];
	outputs[VAR_EXP_SPEC_FLAG] = fixedZeroWire(garbledCircuit, garblingContext);
	outputs[VAR_ZERO_FLAG] = inputA_copy[VAR_ZERO_FLAG];

	Int_Representation_ = old_int_rep;
}




int FLOAT_SUM_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int num_inputs, int *inputs, int *outputs)
{
	if (num_inputs < 2)
	{
		memcpy(outputs, inputs, SINGLE_LENGTH * sizeof(int));
		return 0;
	}

	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	int input_copy[num_inputs * SINGLE_LENGTH];
	memcpy(input_copy, inputs, num_inputs * SINGLE_LENGTH * sizeof(int));

	int num_overflow_bits = 1 + lg_flr(num_inputs - 1);

	int add_pairs[num_inputs][VAR_SINGLE_LENGTH];
	int num_pairs = num_inputs;

	for (int i = 0; i < num_inputs; i++)
	{
		memcpy(&add_pairs[i][VAR_MANTISSA], &inputs[SINGLE_LENGTH*i + MANTISSA], 23 * sizeof(int));
		memcpy(&add_pairs[i][VAR_EXPONENT], &inputs[SINGLE_LENGTH*i + EXPONENT], 8 * sizeof(int));
		memcpy(&add_pairs[i][VAR_SIGN], &inputs[SINGLE_LENGTH*i + SIGN], sizeof(int));
		add_pairs[i][VAR_EXP_ZERO_FLAG] = inputs[SINGLE_LENGTH*i + EXP_ZERO_FLAG];
		add_pairs[i][VAR_MANT_ZERO_FLAG] = inputs[SINGLE_LENGTH*i + MANT_ZERO_FLAG];
		add_pairs[i][VAR_EXP_SPEC_FLAG] = inputs[SINGLE_LENGTH*i + EXP_SPEC_FLAG];
		add_pairs[i][VAR_ZERO_FLAG] = inputs[SINGLE_LENGTH*i + ZERO_FLAG];

		SETCONST_Circuit(garbledCircuit, garblingContext, num_overflow_bits, &zero, &add_pairs[i][VAR_MANTISSA + 24]);
		NOT_Gate2(garbledCircuit, garblingContext, inputs[SINGLE_LENGTH*i + EXP_ZERO_FLAG], &add_pairs[i][VAR_MANTISSA + 23]);
	}

	int inputs_are_normal;
	int special_outputs[SINGLE_LENGTH];

	inputs_are_normal = FLOAT_CHECK_SPECIAL_BATCH_Circuit(garbledCircuit, garblingContext, ADDITION, INFTY_EQ_NAN,
														  num_inputs, SINGLE_LENGTH, input_copy, special_outputs);

	int l = 1;
	while (num_pairs > 1)
	{
		if (num_pairs % 2)
			FLOAT_ADD_RAW_Circuit_2I(garbledCircuit, garblingContext, num_overflow_bits,
									 (int *) &add_pairs[0], (int *) &add_pairs[l * (num_pairs - 1)], (int *) &add_pairs[0]);
		num_pairs >>= 1;

		for (int i = 0; i < num_pairs; i++)
			FLOAT_ADD_RAW_Circuit_2I(garbledCircuit, garblingContext, num_overflow_bits,
									 (int *) &add_pairs[l * (2*i)], (int *) &add_pairs[l * (2*i + 1)], (int *) &add_pairs[l * (2*i)]);
		l *= 2;
	}

	outputs[SIGN] = add_pairs[0][VAR_SIGN];
	//NOTE VAR_*_ZERO_FLAGs will be set after the call to FLOAT_CHECK_ZERO() and the following values are placeholders
	//NOTE meanwhile, VAR_EXP_SPEC_FLAG = 0 for assumed normal outputs is set in FLOAT_ADD_RAW*()
	outputs[EXP_ZERO_FLAG] = add_pairs[0][VAR_EXP_ZERO_FLAG];
	outputs[MANT_ZERO_FLAG] = add_pairs[0][VAR_MANT_ZERO_FLAG];
	outputs[EXP_SPEC_FLAG] = add_pairs[0][VAR_EXP_SPEC_FLAG];
	outputs[ZERO_FLAG] = add_pairs[0][ZERO_FLAG];

	//normalization

	int shifted_mantissa[24 + num_overflow_bits];
	int inc_exponent[9];

	memcpy(shifted_mantissa, (int *) &add_pairs[0][VAR_MANTISSA], (24 + num_overflow_bits) * sizeof(int));
	memcpy(inc_exponent, (int *) &add_pairs[0][VAR_EXPONENT], 8 * sizeof(int));
	SETCONST_Circuit(garbledCircuit, garblingContext, 1, &zero, &inc_exponent[8]);

	int overflow;
	int msb_mask[num_overflow_bits];
	int overflow_amt[8];
	int overflow_repr_size = 1 + lg_flr(num_overflow_bits - 1);


	SETCONST_Circuit(garbledCircuit, garblingContext, 8 - overflow_repr_size, &zero, &overflow_amt[overflow_repr_size]);
	MSB_Circuit(garbledCircuit, garblingContext, num_overflow_bits, MASK_AND_INDEX, &shifted_mantissa[24], msb_mask, overflow_amt, &overflow);

	OBLV_SHIFT_Circuit(garbledCircuit, garblingContext, 24 + num_overflow_bits, RIGHT, TRUNC, POSITIVE, num_overflow_bits, overflow_amt, shifted_mantissa, shifted_mantissa);
	memcpy(&outputs[MANTISSA], shifted_mantissa, 23 * sizeof(int));

	ADD_Circuit_2I(garbledCircuit, garblingContext, 16, OVERFLOW, inc_exponent, overflow_amt, inc_exponent);
	memcpy(&outputs[EXPONENT], inc_exponent, 8 * sizeof(int));

	//NOTE exponent underflow is handled by construction of cases
	//NOTE i.e. though some computation may involve exponent underflow, they will be masked out of the final output
	int out_1[SINGLE_LENGTH];
	int out_2[SINGLE_LENGTH];
	int no_exp_overflow;
	int exp_overflow = inc_exponent[8];
	NOT_Gate2(garbledCircuit, garblingContext, exp_overflow, &no_exp_overflow);

	int fixed_nan[SINGLE_LENGTH];
	SET_CONST_FLOAT_Circuit(garbledCircuit, garblingContext, one, mask, zero, fixed_nan);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, fixed_nan, exp_overflow, out_1);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, outputs, no_exp_overflow, out_2);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * SINGLE_LENGTH, XOR, out_1, out_2, outputs);

	FLOAT_CHECK_ZERO_Circuit(garbledCircuit, garblingContext, outputs, outputs);

	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, inputs_are_normal, no_exp_overflow, &inputs_are_normal);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, outputs, inputs_are_normal, outputs);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * SINGLE_LENGTH, XOR, special_outputs, outputs, outputs);

	Int_Representation_ = old_int_rep;
}


int FLOAT_NEG_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int *inputA, int *outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	memcpy(outputs, inputA, SINGLE_LENGTH * sizeof(int));
	NOT_Gate2(garbledCircuit, garblingContext, outputs[SIGN], &outputs[SIGN]);

	Int_Representation_ = old_int_rep;
}



int FLOAT_MUL_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int *inputA, int *inputB, int *outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	int inputs_are_normal;
	int special_outputs[SINGLE_LENGTH];

	inputs_are_normal = FLOAT_CHECK_SPECIAL_Circuit(garbledCircuit, garblingContext, MULTIPLICATION, INFTY_EQ_NAN, inputA, inputB, special_outputs);

	int inputA_copy[SINGLE_LENGTH];
	int inputB_copy[SINGLE_LENGTH];
	memcpy(inputA_copy, inputA, SINGLE_LENGTH * sizeof(int));
	memcpy(inputB_copy, inputB, SINGLE_LENGTH * sizeof(int));

	int inc_exponent[9];
	SETCONST_Circuit(garbledCircuit, garblingContext, 1, &zero, &inc_exponent[8]);
	ADD_Circuit_2I(garbledCircuit, garblingContext, 16, OVERFLOW, &inputA_copy[EXPONENT], &inputB_copy[EXPONENT], inc_exponent);
	memcpy(&outputs[EXPONENT], inc_exponent, 8 * sizeof(int));

	int exp_raw_upper_bd = 384;
	int exp_raw_lower_bd = 126;
	int exp_lower[9];
	int exp_upper[9];
	int exp_overflow[2];
	int exp_underflow[2];
	int exp_abnormal;
	int exp_normal;

	SETCONST_Circuit(garbledCircuit, garblingContext, 9, &exp_raw_upper_bd, exp_upper);
	SETCONST_Circuit(garbledCircuit, garblingContext, 9, &exp_raw_lower_bd, exp_lower);

	CMP_Circuit_2I(garbledCircuit, garblingContext, 18, GEQ, inc_exponent, exp_upper, exp_overflow);
	CMP_Circuit_2I(garbledCircuit, garblingContext, 18, LEQ, inc_exponent, exp_lower, exp_underflow);
	MIXED_OP_Gate(garbledCircuit, garblingContext, OR, exp_overflow[0], exp_underflow[0], &exp_abnormal);
	NOT_Gate2(garbledCircuit, garblingContext, exp_abnormal, &exp_normal);

	FLOAT_EXP_BIAS_Circuit(garbledCircuit, garblingContext, REMOVE, outputs, outputs);

	int in_mulA[24];
	int in_mulB[24];
	int out_mul[48];

	memcpy(in_mulA, &inputA_copy[MANTISSA], 23 * sizeof(int));
	NOT_Gate2(garbledCircuit, garblingContext, inputA_copy[EXP_ZERO_FLAG], &in_mulA[23]);

	memcpy(in_mulB, &inputB_copy[MANTISSA], 23 * sizeof(int));
	NOT_Gate2(garbledCircuit, garblingContext, inputB_copy[EXP_ZERO_FLAG], &in_mulB[23]);

	MUL_Circuit_2I(garbledCircuit, garblingContext, 48, in_mulA, in_mulB, out_mul);

	int mantmul_overflow = out_mul[47];
	int no_mantmul_overflow;
	NOT_Gate2(garbledCircuit, garblingContext, mantmul_overflow, &no_mantmul_overflow);

	int in_xor[46];

	BITMUL_Circuit_2I(garbledCircuit, garblingContext, 23, &out_mul[24], no_mantmul_overflow, in_xor);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, 23, &out_mul[25], mantmul_overflow, &in_xor[23]);

	MIXED_OP_Circuit(garbledCircuit, garblingContext, 46, XOR, in_xor, &outputs[MANTISSA]);
	BITADD_Circuit_2I(garbledCircuit, garblingContext, 8, NO_OVERFLOW, &outputs[EXPONENT], mantmul_overflow, &outputs[EXPONENT]);
	//NOTE *_ZERO_FLAGs will be set after the call to FLOAT_CHECK_ZERO() and the following values are placeholders
	//NOTE meanwhile, EXP_SPEC_FLAG = 0 for assumed normal outputs
	outputs[EXP_ZERO_FLAG] = inputA_copy[EXP_ZERO_FLAG];
	outputs[MANT_ZERO_FLAG] = inputA_copy[MANT_ZERO_FLAG];
	outputs[EXP_SPEC_FLAG] = fixedZeroWire(garbledCircuit, garblingContext);
	outputs[ZERO_FLAG] = inputA_copy[ZERO_FLAG];

	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[SIGN], inputB_copy[SIGN], &outputs[SIGN]);

	int float_zero[SINGLE_LENGTH];
	int fixed_nan[SINGLE_LENGTH];
	int nan_out[SINGLE_LENGTH];
	int zero_out[SINGLE_LENGTH];
	SET_CONST_FLOAT_Circuit(garbledCircuit, garblingContext, one, mask, zero, fixed_nan);
	SET_CONST_FLOAT_Circuit(garbledCircuit, garblingContext, zero, zero, zero, float_zero);

	BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, fixed_nan, exp_overflow[0], nan_out);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, float_zero, exp_underflow[0], zero_out);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, outputs, exp_normal, outputs);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * SINGLE_LENGTH, XOR, nan_out, outputs, outputs);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * SINGLE_LENGTH, XOR, zero_out, outputs, outputs);

	FLOAT_CHECK_ZERO_Circuit(garbledCircuit, garblingContext, outputs, outputs);

	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, inputs_are_normal, exp_normal, &inputs_are_normal);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, outputs, inputs_are_normal, outputs);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * SINGLE_LENGTH, XOR, special_outputs, outputs, outputs);

	Int_Representation_ = old_int_rep;
}




int FLOAT_SQUARE_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int *inputA, int *outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	int inputs_are_normal;
	int special_outputs[SINGLE_LENGTH];

	inputs_are_normal = FLOAT_CHECK_SPECIAL_Circuit(garbledCircuit, garblingContext, MULTIPLICATION, INFTY_EQ_NAN, inputA, inputA, special_outputs);

	int inputA_copy[SINGLE_LENGTH];
	memcpy(inputA_copy, inputA, SINGLE_LENGTH * sizeof(int));

	int inc_exponent[8];
	int exp_underflow;
	int exp_overflow = inputA_copy[EXPONENT + 7];

	SHIFT_Circuit(garbledCircuit, garblingContext, 8, 1, LEFT, TRUNC, POSITIVE, &inputA_copy[EXPONENT], inc_exponent);
	memcpy(&outputs[EXPONENT], inc_exponent, 8 * sizeof(int));

	int exp_abnormal;
	int exp_normal;
	int zero_bits[2];
	SETCONST_Circuit(garbledCircuit, garblingContext, 2, &zero, zero_bits);
	CMP_Circuit_2I(garbledCircuit, garblingContext, 4, EQ, &inputA_copy[EXPONENT + 6], zero_bits, &exp_underflow);
	MIXED_OP_Gate(garbledCircuit, garblingContext, OR, exp_overflow, exp_underflow, &exp_abnormal);
	NOT_Gate2(garbledCircuit, garblingContext, exp_abnormal, &exp_normal);

	FLOAT_EXP_BIAS_Circuit(garbledCircuit, garblingContext, REMOVE, outputs, outputs);

	int in_mulA[24];
	int in_mulB[24];
	int out_mul[48];

	memcpy(in_mulA, &inputA_copy[MANTISSA], 23 * sizeof(int));
	NOT_Gate2(garbledCircuit, garblingContext, inputA_copy[EXP_ZERO_FLAG], &in_mulA[23]);

	int stopping_split = 24 >> (1 + (lg_flr(24) >> 1));
	SQUARE_2R_G_Circuit(garbledCircuit, garblingContext, 48, in_mulA, out_mul, stopping_split);

	int mantmul_overflow = out_mul[47];
	int no_mantmul_overflow;
	NOT_Gate2(garbledCircuit, garblingContext, mantmul_overflow, &no_mantmul_overflow);

	int in_xor[46];

	BITMUL_Circuit_2I(garbledCircuit, garblingContext, 23, &out_mul[24], no_mantmul_overflow, in_xor);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, 23, &out_mul[25], mantmul_overflow, &in_xor[23]);

	MIXED_OP_Circuit(garbledCircuit, garblingContext, 46, XOR, in_xor, &outputs[MANTISSA]);
	BITADD_Circuit_2I(garbledCircuit, garblingContext, 8, NO_OVERFLOW, &outputs[EXPONENT], mantmul_overflow, &outputs[EXPONENT]);
	//NOTE *_ZERO_FLAGs will be set after the call to FLOAT_CHECK_ZERO() and the following values are placeholders
	//NOTE meanwhile, EXP_SPEC_FLAG = 0 for assumed normal outputs
	outputs[EXP_ZERO_FLAG] = inputA_copy[EXP_ZERO_FLAG];
	outputs[MANT_ZERO_FLAG] = inputA_copy[MANT_ZERO_FLAG];
	outputs[EXP_SPEC_FLAG] = fixedZeroWire(garbledCircuit, garblingContext);
	outputs[ZERO_FLAG] = inputA_copy[ZERO_FLAG];

	outputs[SIGN] = fixedZeroWire(garbledCircuit, garblingContext);

	int float_zero[SINGLE_LENGTH];
	int fixed_nan[SINGLE_LENGTH];
	int nan_out[SINGLE_LENGTH];
	int zero_out[SINGLE_LENGTH];
	SET_CONST_FLOAT_Circuit(garbledCircuit, garblingContext, one, mask, zero, fixed_nan);
	SET_CONST_FLOAT_Circuit(garbledCircuit, garblingContext, zero, zero, zero, float_zero);

	BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, fixed_nan, exp_overflow, nan_out);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, float_zero, exp_underflow, zero_out);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, outputs, exp_normal, outputs);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * SINGLE_LENGTH, XOR, nan_out, outputs, outputs);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * SINGLE_LENGTH, XOR, zero_out, outputs, outputs);

	FLOAT_CHECK_ZERO_Circuit(garbledCircuit, garblingContext, outputs, outputs);

	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, inputs_are_normal, exp_normal, &inputs_are_normal);
	BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, outputs, inputs_are_normal, outputs);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * SINGLE_LENGTH, XOR, special_outputs, outputs, outputs);

	Int_Representation_ = old_int_rep;
}


//Comparison function which handles eq, neq, les, leq, gre, geq based on runtime value of comp_type
//where A is in inputs[0..split-1], B is in inputs[split..2*split-1]
//We read A CMP B for CMP (comp_type) in {GEQ, LEQ, LES, GRT, NEQ, EQ}
//Alternatively, CMP (comp_type) can be in {B_LEQ_A, A_LEQ_B, A_LES_B, B_LES_A, A_NEQ_B, A_EQ_B}
//CAUTION when comparison type is *not* EQ or NEQ, then there are two output values
//CAUTION in these cases, the requested comparison is in outputs[0], and A NEQ B is in outputs[1]
//NOTE by doing this, all relations between A and B can be obtained with one function call and 4 additional gates

int FLOAT_CMP_Circuit_2I(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int comp_type, int ininity_type, int *inputA, int *inputB, int* outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	int testing_eq_only = comp_type & 4;
	int testing_strict_inequality = comp_type & 2;
	int branch = comp_type & 1;

	int same_sign;
	int mixed_sign;
	int A_neq_B;
	int A_cmp_B;

	int inputA_copy[SINGLE_LENGTH];
	int inputB_copy[SINGLE_LENGTH];
	memcpy(inputA_copy, inputA, SINGLE_LENGTH * sizeof(int));
	memcpy(inputB_copy, inputB, SINGLE_LENGTH * sizeof(int));

	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, inputA_copy[SIGN], inputB_copy[SIGN], &mixed_sign);
	NOT_Gate2(garbledCircuit, garblingContext, mixed_sign, &same_sign);

	int mantA[24];
	int mantB[24];

	memcpy(mantA, &inputA_copy[MANTISSA], 23 * sizeof(int));
	memcpy(mantB, &inputB_copy[MANTISSA], 23 * sizeof(int));

	NOT_Gate2(garbledCircuit, garblingContext, inputA_copy[EXP_ZERO_FLAG], &mantA[23]);
	NOT_Gate2(garbledCircuit, garblingContext, inputA_copy[EXP_ZERO_FLAG], &mantB[23]);

	int expA_cmp_expB[2];
	int mantA_cmp_mantB[2];

	CMP_Circuit_2I(garbledCircuit, garblingContext, 16, testing_eq_only ? NEQ : GRT,
				   branch == 0 ? &inputA_copy[EXPONENT] : &inputB_copy[EXPONENT], branch == 0 ? &inputB_copy[EXPONENT] : &inputA_copy[EXPONENT], expA_cmp_expB);
	CMP_Circuit_2I(garbledCircuit, garblingContext, 48, testing_eq_only ? NEQ : GRT,
				   branch == 0 ? mantA : mantB, branch == 0 ? mantB : mantA, mantA_cmp_mantB);

	int expA_neq_expB = testing_eq_only ? expA_cmp_expB[0] : expA_cmp_expB[1];
	int mantA_neq_mantB = testing_eq_only ? mantA_cmp_mantB[0] : mantA_cmp_mantB[1];
	int expA_eq_expB;

	MIXED_OP_Gate(garbledCircuit, garblingContext, OR, mixed_sign, expA_neq_expB, &A_neq_B);
	MIXED_OP_Gate(garbledCircuit, garblingContext, OR, A_neq_B, mantA_neq_mantB, &A_neq_B);
	NOT_Gate2(garbledCircuit, garblingContext, expA_neq_expB, &expA_eq_expB);

	int exp_special_bits[8];
	int A_is_special;
	int B_is_special;
	int nan_input_detected;
	int no_nan_input_detected;

	if (ininity_type == INFTY_EQ_NAN)
	{
		SETCONST_Circuit(garbledCircuit, garblingContext, 8, &mask, exp_special_bits);
		CMP_Circuit_2I(garbledCircuit, garblingContext, 16, EQ, &inputA_copy[EXPONENT], exp_special_bits, &A_is_special);
		CMP_Circuit_2I(garbledCircuit, garblingContext, 16, EQ, &inputB_copy[EXPONENT], exp_special_bits, &B_is_special);
		MIXED_OP_Gate(garbledCircuit, garblingContext, OR, A_is_special, B_is_special, &nan_input_detected);
		NOT_Gate2(garbledCircuit, garblingContext, nan_input_detected, &no_nan_input_detected);
	}
	else
	{
		////TODO handle infinity != NaN cases
	}

	if (testing_eq_only) {
		if (comp_type == EQ) {
			NOT_Gate2(garbledCircuit, garblingContext, A_neq_B, &outputs[0]);
		}
		else
			outputs[0] = A_neq_B;

		MIXED_OP_Gate(garbledCircuit, garblingContext, AND, outputs[0], no_nan_input_detected, &outputs[0]);
		MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, outputs[0], nan_input_detected, &outputs[0]);

		return 0;
	}

	int true_cmp_by_sign = same_sign;
	int true_cmp_by_mant = mantA_cmp_mantB[0];
	int true_cmp_by_mant_or_exp = expA_cmp_expB[0];

	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, true_cmp_by_sign, branch == 0 ? inputB_copy[SIGN] : inputA_copy[SIGN], &true_cmp_by_sign);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, true_cmp_by_mant, expA_eq_expB, &true_cmp_by_mant);
	MIXED_OP_Gate(garbledCircuit, garblingContext, OR, true_cmp_by_mant_or_exp, true_cmp_by_mant, &true_cmp_by_mant_or_exp);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, true_cmp_by_mant_or_exp, mixed_sign, &true_cmp_by_mant_or_exp);
	MIXED_OP_Gate(garbledCircuit, garblingContext, OR, true_cmp_by_mant_or_exp, true_cmp_by_sign, &A_cmp_B);

	if (testing_strict_inequality)
	{
		//A >? B on branch 0, while B >? A on branch 1
		outputs[0] = A_cmp_B;
	}
	else
	{
		//A <=? B on branch 0, while B <=? A on branch 1
		NOT_Gate2(garbledCircuit, garblingContext, A_cmp_B, &outputs[0]);
	}

	outputs[1] = A_neq_B;

	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, outputs[0], no_nan_input_detected, &outputs[0]);
	MIXED_OP_Gate(garbledCircuit, garblingContext, AND, outputs[1], no_nan_input_detected, &outputs[1]);
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, outputs[0], nan_input_detected, &outputs[0]);
	MIXED_OP_Gate(garbledCircuit, garblingContext, XOR, outputs[1], nan_input_detected, &outputs[1]);

	Int_Representation_ = old_int_rep;
}



int FLOAT_SHIFT_Circuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int shift_amount, int direction, int infinity_type, int *inputA, int *outputs)
{
	int old_int_rep = Int_Representation_;
	Int_Representation_ = UNSIGNED;

	int inputA_copy[SINGLE_LENGTH];
	memcpy(inputA_copy, inputA, SINGLE_LENGTH * sizeof(int));
	memcpy(outputs, inputA, SINGLE_LENGTH * sizeof(int));

	int adj_exponent[9];
	int shift_amt_bits[8];
	int exp_overunderflow;
	int no_exp_flow;
	SETCONST_Circuit(garbledCircuit, garblingContext, 8, &shift_amount, shift_amt_bits);
	SETCONST_Circuit(garbledCircuit, garblingContext, 1, &zero, &adj_exponent[8]);

	if (direction == LEFT)
	{
		ADD_Circuit_2I(garbledCircuit, garblingContext, 16, OVERFLOW, &inputA_copy[EXPONENT], shift_amt_bits, adj_exponent);
		//NOTE we are incrementing so that overflow will also indicate expoenent == -1, and remove the bit again below
		INC_Circuit2(garbledCircuit, garblingContext, 9, NO_OVERFLOW, adj_exponent, adj_exponent);
	}
	else
		SUB_Circuit3_2I(garbledCircuit, garblingContext, 16, UNDERFLOW, &inputA_copy[EXPONENT], shift_amt_bits, adj_exponent);

	exp_overunderflow = adj_exponent[8];
	NOT_Gate2(garbledCircuit, garblingContext, exp_overunderflow, &no_exp_flow);

	if (direction == LEFT)
		DEC_Circuit2(garbledCircuit, garblingContext, 9, NO_UNDERFLOW, adj_exponent, adj_exponent);

	memcpy(&outputs[EXPONENT], adj_exponent, 8 * sizeof(int));

	int float_zero[SINGLE_LENGTH];
	int fixed_nan[SINGLE_LENGTH];
	int flowed_outputs[SINGLE_LENGTH];
	SET_CONST_FLOAT_Circuit(garbledCircuit, garblingContext, one, mask, zero, fixed_nan);
	SET_CONST_FLOAT_Circuit(garbledCircuit, garblingContext, zero, zero, zero, float_zero);

	if (direction == LEFT)
		BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, fixed_nan, exp_overunderflow, flowed_outputs);
	else
		BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, float_zero, exp_overunderflow, flowed_outputs);

	BITMUL_Circuit_2I(garbledCircuit, garblingContext, SINGLE_LENGTH, outputs, no_exp_flow, outputs);
	MIXED_OP_Circuit_2I(garbledCircuit, garblingContext, 2 * SINGLE_LENGTH, XOR, flowed_outputs, outputs, outputs);

	Int_Representation_ = old_int_rep;
}




