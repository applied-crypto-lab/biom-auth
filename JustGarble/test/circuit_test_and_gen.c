
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


#include <time.h>
#include <dirent.h>
//#include <math.h>
#include "../include/bio_circuits.h"
#include "../include/bio_auth.h"

#define MIN_NUM_TIME_TRIALS 10
#define NUM_TIME_TRIALS_STATIC 100
#define SQRT_EST(N) (N >> (1 + (lg_flr(N) >> 1)))
#define NUM_TIME_TRIALS_DYNAMIC (MIN_NUM_TIME_TRIALS) + SQRT_EST((int) 24000000 / garbledCircuit.q)
#define CUSTOM 0
#define HD 1
#define ED 2
#define CIRCUIT_FILE 3
#define FILE_ALG (Num_Algs - 2)
#define ALL_ALGS (Num_Algs - 1)


const char *alg_str[] = {"cust", "hd", "cs", "ed", "file", "all"};

const char *opt_str[] = {"new", "mal", "sha3-256"};

const char *alg_descr[] = {"Custom Alg", "Hamming Distance", "Cosine Similarity", "Euclidean Distance", "Alg loaded from file", "All Algs"};

const char *opt_descr[] = {
	"if you wish to force a new circuit build rather than automatically read from file.",
	//NOTE biometric_auth-specific options beging here; if altered, first_bio_specific_opt_idx should be updated just below
	"if you wish to include commitment checking and output the result as a second bit.",
	"if you wish to use SHA3-256 as the commitment function (default is SHA2-256)",
};
int first_bio_specific_opt_idx = 1;


void (*build_func[])(int, int, char*, int) = {NULL, *build_hamming, *build_cosine, *build_euclidean};


int Int_Representation_ = UNSIGNED;
int Running_Consistency_Checks_ = 0;

int Num_Algs = sizeof(alg_str) / sizeof(char*);
int Num_Opts = sizeof(opt_str) / sizeof(char*);




int arg_check(int argc, char **argv, int *task, int *chosen_alg, int *num_inputs, int *input_length, int *new_build){

	if (argc < 2) return -1;
	int check = -1;
	for (int i = 0; i < Num_Algs; i++) {
		check = (strcmp(argv[1], alg_str[i]) == 0) ? 0 : -1;
		if (check == 0){
			*chosen_alg = i;
			break;
		}
	}
	if ((check >= 0) && (*chosen_alg != FILE_ALG)) {
		if (argc < 3) return -1;
		check = strtouint(argv[2], num_inputs);
		check -= (*num_inputs < 0);
	}
	if ((check >= 0) && (*chosen_alg != FILE_ALG)) {
		if (argc < 4) return -1;
		check = strtouint(argv[3], input_length);
		check -= (*input_length < 0);
	}
	if ((check >= 0) && (argc >= 5) && (*chosen_alg != FILE_ALG)) {
		*new_build = 0;
		for (int i = 4; i < argc; i++) {
			*new_build |= (strcmp(argv[i], "new") == 0) ? 1 : 0;
			Malicious_Security_ |= (strcmp(argv[i], "mal") == 0) ? 1 : 0;
			if (strcmp(argv[i], "sha3-256") == 0)
				Commit_Func_ = SHA3_256;
		}
	}

	return check;
}


int get_circuit_file(char *circuit_file) {

	if (chdir(CIRCUIT_DIR_) == -1) {
		printf("Could not open circuit file directory.\n\n");
		return -1;
	}

	char cwd[FNAME_LEN_];
	getcwd(cwd, FNAME_LEN_);

	char *found_files[MAX_FILES_];
	struct dirent *dir;
	DIR *d;
	int f_count = 0;

	if ((d = opendir(cwd)) == NULL) {
		printf("Could not open circuit file directory.\n\n");
		return -1;
	}
	while ((dir = readdir(d)) != NULL) {
		if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0)
			continue;
		found_files[f_count] = (char*) malloc(FNAME_LEN_);
		strcpy(found_files[f_count++], dir->d_name);
	}

	int choice;
	int file_selected = 0;
	while (!file_selected) {
		printf("\nThe files currently stored in the circuit file directory are:\n\n");
		for (int i = 0; i < f_count; i++)
			printf("%i:\t%s\n", i+1, found_files[i]);
		printf("\nPlease select a number corresponding to a listed file, or 0 to exit.\n\nChoice? ");
		file_selected = scanf("%u", &choice) && (choice >= 0) && (choice <= f_count);
	}

	if (choice != 0) {
		strcpy(circuit_file, found_files[choice - 1]);
	}
	for (int i = 0; i < f_count; i++) {
		free(found_files[i]);
	}
	return choice;
}



void describe_usage() {

	int offset;
	char usage_msg[4096];
	offset = sprintf(usage_msg, "\nUsage: circuit_test_and_gen <algorithm> <num inputs> <input length> <opts...>");
	offset += sprintf(usage_msg + offset, "\n\n<algorithm> can be one of: ");
	for (int i = 0; i < Num_Algs; i++) {
		offset += sprintf(usage_msg + offset, "\n\t%s - ", alg_str[i]);
		offset += sprintf(usage_msg + offset, "%s", alg_descr[i]);
	}
	offset += sprintf(usage_msg + offset, "\n\nIf <algorithm> == file, then either\n\t(1) the next argument is a filename, which should be found in the circuit file directory, or\n\t(2) no argument follows, and a menu listing the files in the circuit directory will be provided, with the option to select one for simulation.\n");
	offset += sprintf(usage_msg + offset, "\n<num inputs> and <input length> apply to <algorithm> != file, and must be unsigned integers signifying a number of inputs, and respectively, the length of each, which are appropriate for the chosen algorithm.\n\n");
	offset += sprintf(usage_msg + offset, "if <algorithm> != file, then <opts...> may be:");
	offset += sprintf(usage_msg + offset, "\n\nGeneral options:");
	for (int i = 0; i < Num_Opts; i++) {
		if (i == first_bio_specific_opt_idx)
			offset += sprintf(usage_msg + offset, "\n\nBiometric authentication specific options:");
		offset += sprintf(usage_msg + offset, "\n\t%s - ", opt_str[i]);
		offset += sprintf(usage_msg + offset, "%s\t\t", opt_descr[i]);
	}
	offset += sprintf(usage_msg + offset, "\n\nNote that you may issue 'make cleanscd' to delete all saved circuit files.\n\n");
	printf("%s", usage_msg);
}



int main(int argc, char **argv) {

	srand(time(NULL));
	seedRandom();

	int new_build = 0;
	int task, chosen_alg, num_inputs, input_length;

	if (arg_check(argc, argv, &task, &chosen_alg, &num_inputs, &input_length, &new_build) < 0){
		describe_usage();
		return 0;
	}

	for (int this_alg = 0; this_alg < ALL_ALGS; this_alg++) {
		if ((chosen_alg == this_alg) || ((chosen_alg == ALL_ALGS) && (this_alg != FILE_ALG))) {

			char circuit_file[FNAME_LEN_];

			if (chosen_alg == FILE_ALG) {
				if (argc >= CIRCUIT_FILE) {
					sprintf(circuit_file, "%s%s", CIRCUIT_DIR_, argv[CIRCUIT_FILE]);
					if (access(circuit_file, F_OK) == FAILURE) {
						if (!get_circuit_file(circuit_file))
							return 0;
					}
				}
				else if(!get_circuit_file(circuit_file)) return 0;
			}
			else {
				build_func[this_alg](num_inputs, input_length, circuit_file, RETURN_FILE_NAME);
				if (new_build || access(circuit_file, F_OK) == FAILURE) {
					build_func[this_alg](num_inputs, input_length, circuit_file, BUILD_CIRCUIT);
					new_build = 1;
				}
			}

			GarbledCircuit garbledCircuit;
			if (readCircuitFromFile(&garbledCircuit, circuit_file) == FAILURE) {
				return -1;
			}

			int input_size = garbledCircuit.n;
			int output_size = garbledCircuit.m;


			block *in_labels = (block*) malloc(sizeof(block) * 2 * input_size);
			block *out_labels = (block*) malloc(sizeof(block) * 2 * output_size);

			long num_time_trials = NUM_TIME_TRIALS_DYNAMIC;

			char sim_msg[4096];
			int offset = sprintf(sim_msg, "\n****************************************\n\nSimulating ");
			if (this_alg != FILE_ALG) {
				offset += sprintf(sim_msg + offset, "%s", alg_descr[this_alg]);
			}
			offset += sprintf(sim_msg + offset, " from file %s", circuit_file);
			if (this_alg != FILE_ALG) {
				offset += sprintf(sim_msg + offset, "\nfor %i inputs, each of length %u", num_inputs, input_length);
			}
			offset += sprintf(sim_msg + offset, ", over a total of %li trials.", num_time_trials * num_time_trials);
			printf("%s", sim_msg);

			long int timeGarble[num_time_trials];
			long int timeEval[num_time_trials];
			double timeGarbleMedians[num_time_trials];
			double timeEvalMedians[num_time_trials];
			int i, j;
			for (j = 0; j < num_time_trials; j++) {
				for (i = 0; i < num_time_trials; i++) {
					timeGarble[i] = garbleCircuit(&garbledCircuit, in_labels, out_labels);
					timeEval[i] = timedEval(&garbledCircuit, in_labels);
				}
				timeGarbleMedians[j] = ((double) median((int*) timeGarble, num_time_trials))/ garbledCircuit.q;
				timeEvalMedians[j] = ((double) median((int*) timeEval, num_time_trials))/ garbledCircuit.q;
			}
			double garblingTime = doubleMean(timeGarbleMedians, num_time_trials);
			double evalTime = doubleMean(timeEvalMedians, num_time_trials);
			printf("\n\nResults:\n\n");
			printf("Garbling time (cycles/gate): %lf\n", garblingTime);
			printf("Evaluation time (cycles/gate): %lf\n", evalTime);
			printf("Num gates: %d\n", garbledCircuit.q);
			printf("Num Wires: %d\n\n", garbledCircuit.r);
			printf("Garbling cycles: %lu\n", (unsigned long) garblingTime * garbledCircuit.q);
			printf("Evaluation cycles: %lu\n", (unsigned long) evalTime * garbledCircuit.q);
			printf("Total cycles: %lu\n", (unsigned long) (garblingTime + evalTime) * garbledCircuit.q);
			printf("****************************************\n");

			free(in_labels);
			free(out_labels);
			removeGarbledCircuit(&garbledCircuit);
		}
	}
	return 0;
}

