
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


#include "../include/bio_common.h"


int lg_flr(int x){

	int count = 0;
	while (x > 1){
		x >>= 1;
		count += 1;
	}
	return count;
}



int strtouint(char *str, int *result){

	char *sptr = str;
	int slen = strlen(str);
	while (isdigit(*sptr++)){}
	if (slen == (sptr - str - 1)){
		*result = atoi(str);
		return 0;
	}
	return -1;
}



void int_to_bit_vector(int x, int *v, int input_length){

	for (int i = 0; i < input_length; i ++) {
		v[i] = x & 1;
		x >>= 1;
	}
}



int bit_vector_to_int(int *v, int input_length) {

	int r = 0;
	for (int i = 0; i < input_length; i ++) {
		r += v[i] << i;
	}
	return r;
}



void intarr_to_bit_vector(int *x, int *v, int input_length)
{
	int i = 0;
	int j = 0;
	int d = x[0];

	while ((i * 8 * sizeof(int)) + j < input_length)
	{
		v[j] = d & 1;
		d >>= 1;
		j++;

		if (j == 8 * sizeof(int))
		{
			j = 0;
			d = x[++i];
		}
	}
}



void bit_vector_to_intarr(int *x, int *v, int input_length)
{
	int i = 0;
	int j = 0;
	x[0] = 0;

	while ((i * 8 * sizeof(int)) + j < input_length)
	{
		x[i] += v[j] << j;
		j++;

		if (j == 8 * sizeof(int))
		{
			j = 0;
			x[++i] = 0;
		}
	}
}



void print_bit_vector(int *v, int input_length) {

	printf("[ ");
	for (int i = 0; i < input_length; i++)
		printf("%u ", v[i]);
	printf("]\n");
}



int count_set_bits(int x) {

	int r = 0;
	while (x > 0) {
		r += x & 1;
		x >>= 1;
	}
	return r;
}



void twos_complement(int *in, int *out, int input_length) {

	int i = 0;

	while ((i < input_length) && (in[i] == 0)) {
		out[i] = 0;
		i++;
	}
	if (i < input_length) {
		out[i] = 1;
		for (int j = i+1; j < input_length; j++)
			out[j] = 1 - in[j];
	}
}



void bit_vector_add(int *ina, int *inb, int *out, int input_length) {

	int temp[input_length];
	int carry_in, carry_out;
	temp[0] = ina[0] ^ inb[0];
	carry_in = ina[0] & inb[0];
	for (int i = 1; i < input_length; i++) {
		carry_out = (ina[i] & carry_in) | (inb[i] & carry_in) | (ina[i] & inb[i]);
		temp[i] = ina[i] ^ inb[i] ^ carry_in;
		carry_in = carry_out;
	}
	for (int i = 0; i < input_length; i++) {
		out[i] = temp[i];
	}
}


void bit_vector_add_ovflw(int *ina, int *inb, int *out, int input_length) {

	int temp[input_length];
	int carry_in, carry_out;
	temp[0] = ina[0] ^ inb[0];
	carry_in = ina[0] & inb[0];
	for (int i = 1; i < input_length; i++) {
		carry_out = (ina[i] & carry_in) | (inb[i] & carry_in) | (ina[i] & inb[i]);
		temp[i] = ina[i] ^ inb[i] ^ carry_in;
		carry_in = carry_out;
	}
	out[input_length] = carry_in;
	for (int i = 0; i < input_length; i++) {
		out[i] = temp[i];
	}
}


//expects that inb only contains relevant value at inb[0]
void bit_vector_bin_add(int *ina, int *inb, int *out, int input_length) {

	int temp[input_length];
	int carry_in, carry_out;
	temp[0] = ina[0] ^ inb[0];
	carry_in = ina[0] & inb[0];
	for (int i = 1; i < input_length; i++) {
		carry_out = ina[i] & carry_in;
		temp[i] = ina[i] ^ carry_in;
		carry_in = carry_out;
	}
	for (int i = 0; i < input_length; i++) {
		out[i] = temp[i];
	}
}


//expects that inb only contains relevant value at inb[0]
void bit_vector_bin_add_ovflw(int *ina, int *inb, int *out, int input_length) {

	int temp[input_length];
	int carry_in, carry_out;
	temp[0] = ina[0] ^ inb[0];
	carry_in = ina[0] & inb[0];
	for (int i = 1; i < input_length; i++) {
		carry_out = ina[i] & carry_in;
		temp[i] = ina[i] ^ carry_in;
		carry_in = carry_out;
	}
	out[input_length] = carry_in;
	for (int i = 0; i < input_length; i++) {
		out[i] = temp[i];
	}
}


//it is expected that *out has length 2*input_length
void bit_vector_mul(int *ina, int *inb, int *out, int input_length) {

	for (int i = 0; i < 2 * input_length; i++)
		out[i] = 0;

	for (int i = 0; i < input_length; i++) {
		if (inb[i]) {
			bit_vector_add_ovflw(ina, out + i, out + i, input_length);
		}
	}
}



//expects that ina is 0 or 1
void bit_vector_bitmul(int ina, int *inb, int *out, int input_length) {

	for (int i = 0; i < input_length; i++) {
		out[i] = ina ? inb[i] : 0;
	}
}



//output = b <? a
int bit_vector_les(int *ina, int *inb, int input_length) {

	int i = input_length - 1;
	while ((i > 0) && (ina[i] == inb[i])) i--;
	return inb[i] < ina[i] ? 1 : 0;
}



void bit_vector_not(int *in, int *out, int input_length) {

	for (int i = 0; i < input_length; i++) {
		out[i] = 1 - in[i];
	}
}



void bit_vector_min(int *ina, int *inb, int *out, int input_length) {

	int b_les_a = bit_vector_les(ina, inb, input_length);
	for (int i = 0; i < input_length; i++) {
		if (b_les_a) {
			out[i] = inb[i];
		}
		else {
			out[i] = ina[i];
		}
	}
}



void bit_vector_max(int *ina, int *inb, int *out, int input_length) {

	int b_les_a = bit_vector_les(ina, inb, input_length);
	for (int i = 0; i < input_length; i++) {
		if (b_les_a) {
			out[i] = ina[i];
		}
		else {
			out[i] = inb[i];
		}
	}
}



int bit_vector_msb(int *inputs, int input_length)
{
	int i = input_length - 1;
	while (!inputs[i])
		i--;

	return i;
}



int int_msb(int x)
{
	int i = 8 * sizeof(int) - 1;
	int mask = 1 << (8 * sizeof(int) - 1);
	while (i >= 0)
	{
		if (x & mask)
			return i;
		mask >>= 1;
		i--;
	}
	return -1;
}





