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


#include "../include/common.h"
#include "../include/garble.h"
#include "../include/check.h"
#include "../include/util.h"
#include "../include/justGarble.h"
#include "../include/bio_common.h"


int checkCircuit(GarbledCircuit *garbledCircuit, InputLabels inputLabels,
				 OutputMap outputMap, int num_inputs, int input_length, int check(int *inputs, int *outputs, int num_inputs, int input_length)) {

	int i, j;
	int n = garbledCircuit->n;
	int m = garbledCircuit->m;
	int split = n / 2;

	block extracted_labels[n];
	block eval_out_map[m];
	int eval_output[m];
	int checkfunc_output[m];
	int inputs[n];

	for (i = 0; i < NUM_TESTS; i++) {
		for (j = 0; j < n; j++) {
			inputs[j] = rand() % 2;
		}
		extractLabels(extracted_labels, inputLabels, inputs, n);
		evaluate(garbledCircuit, extracted_labels, eval_out_map);
		mapOutputs(outputMap, eval_out_map, eval_output, m);
		check(inputs, checkfunc_output, num_inputs, input_length);

		///*
		for (int k = 0; k < num_inputs; k+= input_length)
		{
			printf("\nAt checkCircuit():\n");
			printf("a = ");
			print_bit_vector(&inputs[k], input_length);
			printf("a = %i\n\n", bit_vector_to_int(&inputs[k], input_length));
			printf("b = ");
			print_bit_vector(&inputs[k + split], input_length);
			printf("b = %i\n\n", bit_vector_to_int(&inputs[k + split], input_length));
		}
		printf("circuit c = ");
		print_bit_vector(eval_output, m);
		printf("circuit c = %i\n\n", bit_vector_to_int(eval_output, m));

		printf("check func c = ");
		print_bit_vector(checkfunc_output, m);
		printf("check func c = %i\n\n", bit_vector_to_int(checkfunc_output, m));
		//*/

		int num_errs = 0;
		for (j = 0; j < m; j++)
		{
			num_errs += eval_output[j] != checkfunc_output[j];
			/*
			if (eval_output[j] != checkfunc_output[j]) {
				fprintf(stderr, "Test run %u check %u failed\n", i, j);
			}
			*/
		}
		printf("Test run %u:\t%u error bits out of %u\n", i, num_errs, m);
	}

	printf("n = %i\tm = %i\n", n, m);

	return 0;
}

unsigned long timedEval(GarbledCircuit *garbledCircuit, InputLabels inputLabels) {

	int n = garbledCircuit->n;
	int m = garbledCircuit->m;
	block extracted_labels[n];
	block outputs[m];
	int j;
	int inputs[n];
	unsigned long startTime, endTime;
	unsigned long sum = 0;
	for (j = 0; j < n; j++) {
		inputs[j] = rand() % 2;
	}
	extractLabels(extracted_labels, inputLabels, inputs, n);
	startTime = RDTSC;
	evaluate(garbledCircuit, extracted_labels, outputs);
	endTime = RDTSC;
	sum = endTime - startTime;
	return sum;

}

