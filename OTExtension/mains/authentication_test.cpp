
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


#include "bio_auth.h"

#include <cstdlib>
#include <vector>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <memory>
#include <string>

#include <gmp.h>

#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include "../ot/iknp-ot-ext-snd.h"
#include "../ot/iknp-ot-ext-rec.h"
#include "../ot/alsz-ot-ext-snd.h"
#include "../ot/alsz-ot-ext-rec.h"
#include "../ot/nnob-ot-ext-snd.h"
#include "../ot/nnob-ot-ext-rec.h"
#include "../ot/kk-ot-ext-snd.h"
#include "../ot/kk-ot-ext-rec.h"
#include <ENCRYPTO_utils/cbitvector.h>
#include "../ot/xormasking.h"
#include <ENCRYPTO_utils/rcvthread.h>
#include <ENCRYPTO_utils/sndthread.h>
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/timer.h>
#include <ENCRYPTO_utils/parse_options.h>

#include "../extern/ENCRYPTO_utils/src/ENCRYPTO_utils/connection.h"
#include "../extern/ENCRYPTO_utils/src/ENCRYPTO_utils/socket.h"
//#include "../extern/ENCRYPTO_utils/src/ENCRYPTO_utils/timer.h"

extern "C" {
	#include "../../JustGarble/include/common.h"
	#include "../../JustGarble/include/bio_common.h"
	#include "../../JustGarble/include/justGarble.h"
	#include "../../JustGarble/include/util.h"
}


//NOTE The security parameter kappa for both OTExt and our work. Valid choices within OTExt are 80, 112, 128.
//CAUTION JG encryption key is currently generated to this size and is inflexible

uint32_t ot_sec_param = 128;
uint32_t ot_sec_param_bytes = ceil_divide(ot_sec_param, 8);
uint32_t ot_stat_param = 40;

#define SUPPLEMENTAL_INPUT_BITS 128

int my_id = S1_ID;
field_type ftype = ECC_FIELD;;
MaskingFunction* mask_func;

// Naor-Pinkas OT
//BaseOT* bot;
OTExtSnd *sender;
OTExtRec *receiver;

SndThread* sndthread;
RcvThread* rcvthread;

PeerNet *peer_net;
Timer *timer;

int tcount = 0;

std::string pn_config_file = "pn-config-local";
std::string rsa_prv_keyfile = "";

uint32_t num_OT_threads = 1;
uint32_t num_baseOTs;
uint32_t num_checks;
uint32_t runs = 1;
uint32_t nsndvals = 2;
snd_ot_flavor stype = Snd_OT;
rec_ot_flavor rtype = Rec_OT;
bool use_min_ent_cor_rob = false;
ot_ext_prot prot = ALSZ;	//NOTE - use ALSZ for malicious, IKNP for semihonest; see literature

BYTE ack = ACK;
uint32_t bytes_in, bytes_out;
std::string id_str[] = {"S1", "S2", "C"};

uint32_t verifying_ot = 1;
uint32_t using_combined_labels = 0;
int test_run_num = -1;

static const char* local_const_seed[3] = {"437398417012387813714564100", "15657566154164561", "4344225571187781480250227846347538156"};

//Distance functions and corresponding JG circuit filename prefixes
#define HD 0
#define ED 1
#define CS 2

std::string tm_str[] = {"sh", "mal"};
uint32_t num_tms = sizeof(tm_str) / sizeof(std::string);
std::string chosen_tm_str = "sh";
int chosen_tm = SEMIHONEST;

std::string df_str[] = {"hd", "cs", "ed"};
uint32_t num_dfs = sizeof(df_str) / sizeof(std::string);
std::string chosen_df_str = "cs";
uint32_t chosen_df = 1;

std::string vf_str[] = {"sha2-256", "sha3-256"};
uint32_t num_vfs = sizeof(vf_str) / sizeof(std::string);
std::string chosen_vf_str = "sha2-256";
uint32_t chosen_vf = 0;

std::string OT_send_addr = "127.0.0.1";	//localhost default
std::string OT_recv_addr = "127.0.0.1";	//localhost default

std::unique_ptr<CSocket> OT_socket = NULL;

uint32_t OT_port = 44505;

int num_inputs = 192;	//biometric vector; same meaning as in JustGarble
int input_length = 8;	//bio-vector component length; same meaning as in JustGarble

int computing_offline = 1;
int computing_online = 1;

int verbose = 1;
double elapsed;
std::vector<double> test_results;

/**
 * returns a random mpz_t with bitlen len generated from dev/urandom, based on aby_prng
 */

void uc_prng(unsigned char *rnd, mp_bitcnt_t bitlen)
{
	size_t byte_count = ceil_divide(bitlen, 8);

	int furandom = open("/dev/urandom", O_RDONLY);
	if (furandom < 0)
	{
		std::cerr << "Error in opening /dev/urandom: utils.cpp:aby_prng()" << std::endl;
		exit(1);
	}
	else
	{
		size_t len = 0;
		while (len < byte_count) {
			ssize_t result = read(furandom, rnd + len, byte_count - len);
			if (result < 0) {
				std::cerr << "Error in generating random number: utils.cpp:aby_prng()" << std::endl;
				exit(1);
			}
			len += result;
		}
		close(furandom);
	}

	//set MSBs to zero, if we are not working on full bytes
	rnd[byte_count - 1] &= (255 >> ((8 - bitlen) % 8));
}



int lg_flr(unsigned x)
{
	unsigned count = 0;
	while (x > 1)
	{
		x >>= 1;
		count += 1;
	}
	return count;
}



void Cleanup()
{
	delete sndthread;
	delete rcvthread;
	delete peer_net;
}




/**
 * prints a block (aka __m128i) as (the integer values of) an array of bytes
 */

void print_block(block *b, int bracketing)
{
	if (bracketing) printf("\n");
	for (int i = 0; i < sizeof(block); i ++)
	{
		printf("%u ", ((unsigned char *) b)[i]);
	}
	if (bracketing) printf("\n");
}



/**
 * the following two functions set up OT sender and reciver, respectively
 */

void InitOTSender(crypto* crypt, CLock *glock, std::unique_ptr<CSocket>& lsock, bool verifying_ot)
{
	sndthread = new SndThread(lsock.get(), glock);
	rcvthread = new RcvThread(lsock.get(), glock);

	rcvthread->Start();
	sndthread->Start();

	switch(prot)
	{
		case ALSZ: sender = new ALSZOTExtSnd(crypt, rcvthread, sndthread, num_baseOTs, num_checks, ot_sec_param); break;
		case IKNP: sender = new IKNPOTExtSnd(crypt, rcvthread, sndthread); break;
		case NNOB: sender = new NNOBOTExtSnd(crypt, rcvthread, sndthread); break;
		case KK: sender = new KKOTExtSnd(crypt, rcvthread, sndthread, 4096, verifying_ot, false); break;
		default: sender = new ALSZOTExtSnd(crypt, rcvthread, sndthread, num_baseOTs, num_checks); break;
	}

	if(use_min_ent_cor_rob)
		sender->EnableMinEntCorrRobustness();
	sender->ComputeBaseOTs(ftype);
}




void InitOTReceiver(crypto* crypt, CLock *glock, std::unique_ptr<CSocket>& csock, bool verifying_ot)
{
	sndthread = new SndThread(csock.get(), glock);
	rcvthread = new RcvThread(csock.get(), glock);

	rcvthread->Start();
	sndthread->Start();


	switch(prot)
	{
		case ALSZ: receiver = new ALSZOTExtRec(crypt, rcvthread, sndthread, num_baseOTs, num_checks, ot_sec_param); break;
		case IKNP: receiver = new IKNPOTExtRec(crypt, rcvthread, sndthread); break;
		case NNOB: receiver = new NNOBOTExtRec(crypt, rcvthread, sndthread); break;
		case KK: receiver = new KKOTExtRec(crypt, rcvthread, sndthread, 4096, verifying_ot, false); break;
		default: receiver = new ALSZOTExtRec(crypt, rcvthread, sndthread, num_baseOTs, num_checks); break;
	}

	if(use_min_ent_cor_rob)
		receiver->EnableMinEntCorrRobustness();

	receiver->ComputeBaseOTs(ftype);
}



/**
 * the following two functions engage the OT send and recive routines, respectively
 */

int OTSend(CBitVector** OT_all, uint32_t num_inputs, uint32_t input_bitlength, crypto* crypt, CLock *glock, std::unique_ptr<CSocket>& lsock)
{
	CBitVector delta;

	//The masking function with which the values that are sent in the last communication step are processed
	mask_func = new XORMasking(ot_sec_param, delta);
	delta.Create(num_inputs, input_bitlength, crypt);

	bool success = FALSE;
	lsock->ResetSndCnt();
	lsock->ResetRcvCnt();

	success = sender->send(num_inputs, input_bitlength, 2, OT_all, stype, rtype, num_OT_threads, mask_func);

	delete mask_func;
	//delta.delCBitVector();

	return success;
}



int OTRecv(CBitVector* OT_recv_buf, CBitVector* OT_bits, uint32_t num_inputs, uint32_t input_bitlength, crypto* crypt, CLock *glock, std::unique_ptr<CSocket>& csock)
{
	//The masking function with which the values that are sent in the last communication step are processed
	mask_func = new XORMasking(ot_sec_param);

	//OT_recv_buf->Reset();

	bool success = FALSE;
	csock->ResetSndCnt();
	csock->ResetRcvCnt();

	success = receiver->receive(num_inputs, input_bitlength, 2, OT_bits, OT_recv_buf, stype, rtype, num_OT_threads, mask_func);

	delete mask_func;

	return success;
}



/**
 * command line argument parser
 */

int32_t read_test_options(int32_t* argcp, char*** argvp, int* role, int *verbose, int *test_run_num, int* num_inputs, int* input_length, uint32_t* verifying_ot, int *computing_offline, int *computing_online)
{
	int loc_num_inputs = 0, loc_input_length = 0, loc_verbose = 0, loc_test_run_num = 0; int loc_computing_offline = 0; int loc_computing_online = 1;
	bool printhelp = false;

	uint32_t loc_num_baseOTs = 0;
	uint32_t loc_num_checks = 0;
	uint32_t loc_secparam = 0;
	uint32_t loc_statparam = 0;

	parsing_ctx options[] =
	{
		{ (void*) role, T_NUM, "r", "Role: 0/1/2", true, false },
		{ (void*) &chosen_tm_str, T_STR, "tm", "Threat model, default: semi-honest", false, false },
		{ (void*) &loc_verbose, T_NUM, "vb", "Verbose, default: true", false, false },
		{ (void*) test_run_num, T_NUM, "tr", "Test run number, default: -1 (for non-batched testing)", false, false },
		{ (void*) &pn_config_file, T_STR, "fc", "PeerNet configuration filename", false, false },
		{ (void*) &rsa_prv_keyfile, T_STR, "fr", "RSA private key file name", false, false },
		{ (void*) &chosen_df_str, T_STR, "df", "Distance function, default: cs (cosine similarity)", false, false },
		{ (void*) &chosen_vf_str, T_STR, "vf", "Commitment verification function, default: sha2_256)", false, false },
		{ (void*) &loc_num_inputs, T_NUM, "in", "Number of biometric inputs (i.e. vector size), default: 192", false, false },
		{ (void*) &loc_input_length, T_NUM, "il", "Input length (biometric input vector), default: 8", false, false },
		{ (void*) &loc_num_baseOTs, T_NUM, "nbo", "Number of base OTs, default: 190", false, false },
		{ (void*) &loc_num_checks, T_NUM, "ncc", "Number of consistency checks, default: 380", false, false },
		{ (void*) &loc_secparam, T_NUM, "sk", "SH security parameter (kappa), default: 128", false, false },
		{ (void*) &loc_statparam, T_NUM, "sr", "SH statistical parameter (rho), default: 40", false, false },
		{ (void*) verifying_ot, T_NUM, "v", "Verifying OTs?, default: true", false, false },
		{ (void*) &loc_computing_offline, T_NUM, "coff", "Computing offline times and comm?, default: true", false, false },
		{ (void*) &loc_computing_online, T_NUM, "con", "Computing online times and comm?, default: true", false, false },
		{ (void*) &printhelp, T_FLAG, "h", "Print help", false, false }
	};

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx)))
	{
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		std::exit(EXIT_FAILURE);
	}
	if(printhelp)
	{
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		std::exit(EXIT_FAILURE);
	}

	assert(*role < 3);
	if (chosen_tm_str.compare("mal") == 0)
	{
			chosen_tm = MALICIOUS;
	}
	if (chosen_df_str.compare("") != 0)
	{
		while (chosen_df < num_dfs) {
			if (df_str[chosen_df].compare(chosen_df_str) == 0) break;
			chosen_df++;
		}
		assert(chosen_df < num_dfs);
	}
	if (chosen_vf_str.compare("") != 0)
	{
		while (chosen_vf < num_vfs) {
			if (vf_str[chosen_vf].compare(chosen_vf_str) == 0) break;
			chosen_vf++;
		}
		assert(chosen_vf < num_vfs);
	}
	if(loc_num_inputs != 0)
	{
		assert(loc_num_inputs > 7);
		*num_inputs = (uint16_t) loc_num_inputs;
	}
	if(loc_input_length != 0)
	{
		assert(loc_input_length > 3);
		*input_length = (uint16_t) loc_input_length;
	}
	if(loc_secparam != 0)
	{
		assert(loc_secparam >= 128);
		ot_sec_param = loc_secparam;
	}
	if(loc_statparam != 0)
	{
		assert(loc_statparam >= 40);
		ot_stat_param = loc_statparam;
	}
	if(loc_num_baseOTs != 0)
	{
		assert(loc_num_baseOTs > ot_sec_param);
		num_baseOTs = loc_num_baseOTs;
	}
	if(loc_num_checks != 0)
	{
		assert(loc_num_checks >= 2 * num_baseOTs);
		num_checks = loc_num_checks;
	}
	if(loc_computing_offline != 0)
	{
		assert(loc_computing_offline == 1);
		*computing_offline = loc_computing_offline;
	}
	if(loc_computing_online != 1)
	{
		assert(loc_computing_online == 0);
		*computing_online = loc_computing_online;
	}

	return 1;
}

int main(int argc, char** argv)
{
	assert(DEFAULT_BIOMETRIC_INPUT_LENGTH >= COMPRESSED_BIOMETRIC_INPUT_LENGTH);

	read_test_options(&argc, &argv, &my_id, &verbose, &test_run_num, &num_inputs, &input_length, &verifying_ot, &computing_offline, &computing_online);

	int num_input_bits = (num_inputs * input_length) + 64;
	int num_input_bytes = ceil_divide(num_input_bits, 8);

	std::string gc_file = "circuit_files/bio_auth_" + df_str[chosen_df] + "_";
	if (chosen_tm == MALICIOUS)
		gc_file += "mal_" + chosen_vf_str + "_";
	gc_file += std::to_string(num_inputs) + "_" + std::to_string(input_length) + ".scd";
	//NOTE for compatibility with JG function readCircuitFromFile()
	char* gc_file_c = const_cast<char*>(gc_file.c_str());

	std::string test_params = chosen_tm_str + "_" + chosen_df_str;
	std::string comm_res_fname = "results/comm_test_results_" + id_str[my_id] + "_" + test_params + ".txt";

	if (test_run_num < 0)
	{
		std::cout << "\n" << id_str[my_id] << " Initiating test run " << test_run_num << "\n";
		std::cout << "\nNum inputs: " << num_inputs << "\tInput length: " << input_length << "\n";
		std::cout << "Num input bits = " << num_input_bits << "\n";
		std::cout << "Verifying OT: " << verifying_ot << "\n";
		std::cout << "Computing offline phase: " << computing_offline << "\n";
		std::cout << "Computing online phase: " << computing_online << "\n";
		std::cout << "OT Security Parameter (kappa): " << ot_sec_param << "\n";
		std::cout << "Num Base OTs: " << num_baseOTs << "\n";
		std::cout << "Num Consistency checks: " << num_checks << "\n";
		std::cout << "Distance function: " << df_str[chosen_df] << "\n";
		if (chosen_tm == MALICIOUS)
		{
			std::cout << "Verification function: " << vf_str[chosen_vf] << "\n";
			std::cout << "OT Security Parameter (rho): " << ot_stat_param << "\n";
		}
		std::cout << "\nGC file: " << gc_file << "\n\n";
	}
	else if (test_run_num == 0)
	{
		std::ofstream comm_results_file;
		comm_results_file.open(comm_res_fname);

		comm_results_file << "\nNum inputs: " << num_inputs << "\tInput length: " << input_length << "\n";
		comm_results_file << "Num input bits = " << num_input_bits << "\n";
		comm_results_file << "Verifying OT: " << verifying_ot << "\n";
		comm_results_file << "Computing offline phase: " << computing_offline << "\n";
		comm_results_file << "Computing online phase: " << computing_online << "\n";
		comm_results_file << "OT Security Parameter (kappa): " << ot_sec_param << "\n";
		comm_results_file << "Num Base OTs: " << num_baseOTs << "\n";
		comm_results_file << "Num Consistency checks: " << num_checks << "\n";
		comm_results_file <<  "Distance function: " << df_str[chosen_df] << "\n";
		if (chosen_tm == MALICIOUS)
		{
			comm_results_file << "Verification function: " << vf_str[chosen_vf] << "\n";
			comm_results_file << "OT Security Parameter (rho): " << ot_stat_param << "\n";
		}
		comm_results_file << "\nGC file: " << gc_file << "\n\n";
	}

	if (chosen_tm == SEMIHONEST)
	{
		num_baseOTs = 128;
		num_checks = 0;
		ot_ext_prot prot = IKNP;
	}
	else //chosen_tm == MALICIOUS
	{
		num_baseOTs = 190;
		num_checks = 380;
		ot_ext_prot prot = ALSZ;
	}

	BYTE failure, decision;
	BYTE errors_detected = false;
	int bytes_in = 0;
	int bytes_out = 0;
	int tot_bytes_in = 0;
	int tot_bytes_out = 0;

	//in blocks, 1 block per bit

	int num_OT_bits = chosen_df == HD ? num_input_bits : 2 * num_input_bits;
	if (chosen_tm == MALICIOUS)
		num_OT_bits += SUPPLEMENTAL_INPUT_BITS;
	int commitment_size = 256;
	int gc_input_size = num_OT_bits;
	if (chosen_tm == MALICIOUS)
		gc_input_size += commitment_size;

	crypto *crypt = new crypto(ot_stat_param, ot_sec_param, (uint8_t*) local_const_seed[my_id]);
	CLock *glock = new CLock(); // pass this to sender and receiver constructors

	bool resetting_OT_addrs = false;
	unsigned char ack_buf[1];

	if (rsa_prv_keyfile != "")
		resetting_OT_addrs = true;
	else
	{
		if (my_id == S1_ID)
			rsa_prv_keyfile = "prvkeyS1.pem";
		if (my_id == S2_ID)
			rsa_prv_keyfile = "prvkeyS2.pem";
		if (my_id == C_ID)
			rsa_prv_keyfile = "prvkeyC.pem";
	}

	timer = new Timer();

	peer_net = new PeerNet(3, my_id, rsa_prv_keyfile, pn_config_file);

	if (resetting_OT_addrs)
	{
		OT_send_addr = peer_net->peers()[S1_ID].ip_addr;
		OT_recv_addr = peer_net->peers()[S2_ID].ip_addr;
	}

	if (test_run_num >= 0) verbose = false;

	int debug_ctr = 0;

	//NOTE begin individual party branches
	if (my_id == S1_ID)
	{
		//generate runtime random value for S1's share of enrollment biometric (B1)

		mpz_t b_1;
		mpz_init2(b_1, num_input_bits);
		aby_prng(b_1, num_input_bits);

		mpz_t c_1;
		mpz_init2(c_1, num_input_bits);
		aby_prng(c_1, num_input_bits);

		OT_socket = Listen(OT_send_addr, OT_port);
		if (!OT_socket)
		{
			std::cerr << "Listen failed on " << OT_send_addr << ":" << OT_port << "\n";
			std::exit(1);
		}

	 	InitOTSender(crypt, glock, OT_socket, verifying_ot);

		GarbledCircuit garbledCircuit;
		errors_detected = readCircuitFromFile(&garbledCircuit, gc_file_c) < 0;

		if (errors_detected)
		{
			printf("Error reading GC scd file\n");
		}

		assert(garbledCircuit.n == gc_input_size);
		assert(garbledCircuit.m == 2 + chosen_tm);

#ifdef ROW_REDUCTION
		int gtable_size = 3 * garbledCircuit.q;	//in blocks
#else
		int gtable_size = 4 * garbledCircuit.q;	//in blocks
#endif

		group_ACK();

		if (computing_offline)
		{
			//NOTE test run timer starts now; offline time included
			timer->process_timestamp(false, verbose, NULL);
			//NOTE test run timer starts now; offline time included
		}

		unsigned char bhat1_buf[num_input_bytes];
		block *in_labels = (block*) malloc(sizeof(block) * 2 * garbledCircuit.n);
		block *out_labels = (block*) malloc(sizeof(block) * 2 * garbledCircuit.m);

		if (computing_offline)
			timer->process_timestamp(true, verbose, "\nGarbling circuit\n");

		garbleCircuit(&garbledCircuit, in_labels, out_labels);

		if (computing_offline)
			timer->process_timestamp(true, verbose, "Done garbling circuit\n\n");

		block *table_buf = (block*) malloc(gtable_size * sizeof(block));		// assumes no truncation in GC
		//copy garbled table into send buffer
		memcpy(table_buf, &garbledCircuit.garbledTable->table, gtable_size * sizeof(block));

		if (computing_offline)
			timer->process_timestamp(true, verbose, "\nSending garbled table to S2\n");

		bytes_out = peer_net->send_to_peer(S2_ID, (unsigned char*) table_buf, gtable_size * sizeof(block), PLAINTEXT, NULL);
		errors_detected = bytes_out != gtable_size * sizeof(block);

		if (computing_offline)
		{
			timer->process_timestamp(true, verbose, "Done sending garbled table to S2\n");
			tot_bytes_out += bytes_out;
		}

		if (errors_detected)
		{
			printf("Error sending garbled table to S2\n");
		}

		block *s2_label_buf;

		if (chosen_tm == MALICIOUS)
		{
			s2_label_buf = (block*) malloc(commitment_size * sizeof(block));

			//set commitment labels for comparison
			for (int i = 0; i < commitment_size; i++)
			{
				int c_i = mpz_tstbit(c_1, i);
				memcpy(&s2_label_buf[i], &in_labels[(6 * num_input_bits + (2*i + c_i))], sizeof(block));
			}

			if (computing_offline)
				timer->process_timestamp(true, verbose, "\nSending commitment labels to S2\n");

			bytes_out = peer_net->send_to_peer(S2_ID, (unsigned char*) s2_label_buf, commitment_size * sizeof(block), ENCRYPTED, NULL);
			errors_detected = bytes_out != commitment_size * sizeof(block);

			if (computing_offline)
			{
				timer->process_timestamp(true, verbose, "Done sending commitment labels to S2\n\n");
				tot_bytes_out += bytes_out;
			}

			if (errors_detected)
			{
				printf("Error sending commitment labels to S2\n");
			}
		}

		if (!computing_online)
		{
			free(in_labels);
			free(out_labels);
			free(table_buf);
			removeGarbledCircuit(&garbledCircuit);
			mpz_clear(b_1);
			mpz_clear(c_1);
			goto finalization;
		}

		//NOTE synchronization
		peer_net->receive_from_peer(C_ID, ack_buf, 1, PLAINTEXT, NULL);
		peer_net->receive_from_peer(S2_ID, ack_buf, 1, PLAINTEXT, NULL);
		peer_net->send_to_peer(C_ID, ack_buf, 1, PLAINTEXT, NULL);
		peer_net->send_to_peer(S2_ID, ack_buf, 1, PLAINTEXT, NULL);

		if (!computing_offline)
		{
			//NOTE test run timer starts now; offline time NOT included
			timer->process_timestamp(false, verbose, NULL);
			//NOTE test run timer starts now; offline time NOT included
		}

		timer->process_timestamp(true, verbose, "\nReceiving XOR share from C\n");
		bytes_in = peer_net->receive_from_peer(C_ID, bhat1_buf, num_input_bytes, ENCRYPTED, NULL);
		timer->process_timestamp(true, verbose, "Done receiving XOR share from C\n\n");
		errors_detected = bytes_in != num_input_bytes;
		tot_bytes_in += bytes_in;

		//there is no secific creation of delta because JustGarble handles this implicitly within createInputLabels (called from garbleCircuit() from within Garbler_Process_GC())

		block *OT_zero_buf = (block*) malloc(num_OT_bits * sizeof(block));
		block *OT_one_buf = (block*) malloc(num_OT_bits * sizeof(block));

		CBitVector **OT_all = (CBitVector**) malloc(2 * sizeof(CBitVector*));
		for(int i = 0; i < 2; i++)
		{
			OT_all[i] = new CBitVector();
			OT_all[i]->Create(num_OT_bits, 8 * sizeof(block));
		}

		//put extracted labels (based on b_1 bits) into buffer, for transmission to S2
		for (int i = 0; i < num_input_bits; i++)
		{
			int b_i = mpz_tstbit(b_1, i);
			int rhat_i = (bhat1_buf[i / 8] & (1 << (i % 8))) >> (i % 8);
			memcpy(&OT_zero_buf[i], &in_labels[2*i + rhat_i], sizeof(block));
			memcpy(&OT_one_buf[i], &in_labels[(2*i + (rhat_i ^ 1))], sizeof(block));
			memcpy(&OT_zero_buf[num_input_bits + i], &in_labels[2*num_input_bits + 2*i + b_i], sizeof(block));
			memcpy(&OT_one_buf[num_input_bits + i], &in_labels[2*num_input_bits + (2*i + (b_i ^ 1))], sizeof(block));
		}

		mpz_clear(b_1);
		mpz_clear(c_1);

		OT_all[0]->SetBits((BYTE*) OT_zero_buf, 0, num_OT_bits * 8 * sizeof(block));
		OT_all[1]->SetBits((BYTE*) OT_one_buf, 0, num_OT_bits * 8 * sizeof(block));

		timer->process_timestamp(true, verbose, "\nEngaging in OT with S2\n");
		errors_detected = !OTSend(OT_all, num_OT_bits, 8 * sizeof(block), crypt, glock, OT_socket);
		timer->process_timestamp(true, verbose, "Done engaging in OT with S2\n\n");

		if (errors_detected)
		{
			printf("Error engaging in OT with S2\n");
		}

		BYTE verify_success, verify_failure;
		BYTE* elln_buf = (BYTE*) malloc(1 + ((2 + chosen_tm) * sizeof(block)));

		timer->process_timestamp(true, verbose, "\nReceiving output labels from S2\n");
		bytes_in = peer_net->receive_from_peer(S2_ID, elln_buf, 1 + ((2 + chosen_tm) * sizeof(block)), ENCRYPTED, NULL);
		timer->process_timestamp(true, verbose, "Done receiving output labels from S2\n\n");
		errors_detected = bytes_in != 1 + ((2 + chosen_tm) * sizeof(block));
		tot_bytes_in += bytes_in;

		if (errors_detected)
		{
			printf("Error receiving labels from S2\n");
		}

		int accepted_dist;
		int accepted_norm;
		int rejected_dist;
		int accepted_verif;
		int rejected_norm;
		int rejected_verif;

		if (!errors_detected & (elln_buf[(2 + chosen_tm) * sizeof(block)] == 1))
		{
			int accepted_dist = _mm_ucomieq_sd (_mm_castsi128_pd (out_labels[1]), _mm_castsi128_pd (*((block*) elln_buf)));
			int rejected_dist = _mm_ucomieq_sd (_mm_castsi128_pd (out_labels[0]), _mm_castsi128_pd (*((block*) elln_buf)));

			int accepted_norm = _mm_ucomieq_sd (_mm_castsi128_pd (out_labels[3]), _mm_castsi128_pd (*((block*) &elln_buf[sizeof(block)])));
			int rejected_norm = _mm_ucomieq_sd (_mm_castsi128_pd (out_labels[2]), _mm_castsi128_pd (*((block*) &elln_buf[sizeof(block)])));

			if (chosen_tm == MALICIOUS)
			{
				int accepted_verif = _mm_ucomieq_sd (_mm_castsi128_pd (out_labels[5]), _mm_castsi128_pd (*((block*) &elln_buf[2 * sizeof(block)])));
				int rejected_verif = _mm_ucomieq_sd (_mm_castsi128_pd (out_labels[4]), _mm_castsi128_pd (*((block*) &elln_buf[2 * sizeof(block)])));
			}

			if (verbose)
			{
				if (!(accepted_dist || rejected_dist ))
					printf("Distance label mismatch\n");
				else
					printf("Valid distance label received\n");

				if (!(accepted_norm || rejected_norm))
					printf("Normalization label mismatch\n");
				else
					printf("Valid normalization received\n");

				if (chosen_tm == MALICIOUS)
				{
					if (!(accepted_verif || rejected_verif))
						printf("Verification label mismatch\n");
					else
						printf("Valid verification received\n");
				}
			}

			if (accepted_dist && accepted_norm && ((chosen_tm == MALICIOUS) && accepted_verif))
			{
				decision = 1;	//accept C
			}
			else {
				decision = 0;	//reject C
			}
		}
		else
		{
			decision = 4;	//retry, other error(s)
			if (elln_buf[(2 + chosen_tm) * sizeof(block)] != 1)
			{
				printf("S2 signals failure\n");
			}
		}

		if (verbose) printf("\nDecision at S1:\t%u\n\n", decision);

		timer->process_timestamp(true, verbose, "\nSending decision to C\n");
		bytes_out = peer_net->send_to_peer(C_ID, &decision, 1, ENCRYPTED, NULL);
		timer->process_timestamp(true, verbose, "Done sending decision to C\n\n");
		errors_detected = bytes_out != 1;
		tot_bytes_out += bytes_out;

		if (errors_detected)
		{
			printf("Error sending decision to C\n");
		}

		free(table_buf);
		if (chosen_tm == MALICIOUS)
			free(s2_label_buf);
		free(OT_zero_buf);
		free(OT_one_buf);
		free(elln_buf);

		OT_all[0]->delCBitVector();
		OT_all[1]->delCBitVector();
		delete OT_all[0];
		delete OT_all[1];
		free(OT_all);

		removeGarbledCircuit(&garbledCircuit);
		free(in_labels);
		free(out_labels);
	}

	else if (my_id == S2_ID)
	{
		OT_socket = Connect(OT_send_addr, OT_port);
		if (!OT_socket)
		{
			std::cerr << "Connect failed on " << OT_send_addr << ":" << OT_port << "\n";
			std::exit(1);
		}

	 	InitOTReceiver(crypt, glock, OT_socket, verifying_ot);

		GarbledCircuit garbledCircuit;
		errors_detected = readCircuitFromFile(&garbledCircuit, gc_file_c) < 0;

#ifdef ROW_REDUCTION
		int gtable_size = 3 * garbledCircuit.q;	//in blocks
#else
		int gtable_size = 4 * garbledCircuit.q;	//in blocks
#endif

		assert(garbledCircuit.n == gc_input_size);
		assert(garbledCircuit.m == 2 + chosen_tm);

		group_ACK();

		if (computing_offline)
		{
			//NOTE test run timer starts now; offline time included
			timer->process_timestamp(false, verbose, NULL);
			//NOTE test run timer starts now; offline time included
		}

		block *table_buf = (block*) malloc(gtable_size * sizeof(block));		// assumes no truncation in GC
		block *s2_label_buf = (block*) malloc(commitment_size * sizeof(block));

		if (computing_offline)
			timer->process_timestamp(true, verbose, "\nReceiving garbled table from S1\n");

		bytes_in = peer_net->receive_from_peer(S1_ID, (unsigned char*) table_buf, gtable_size * sizeof(block), PLAINTEXT, NULL);
		errors_detected = bytes_in != gtable_size * sizeof(block);

		if (computing_offline)
		{
			timer->process_timestamp(true, verbose, "Done receiving garbled table from S1\n\n");
			tot_bytes_in += bytes_in;
		}

		if (errors_detected)
		{
			printf("Error receiving garbled table from S1\n");
		}

		if (chosen_tm == MALICIOUS)
		{
			if (computing_offline)
				timer->process_timestamp(true, verbose, "\nReceiving commitment labels from S1\n");

			bytes_in = peer_net->receive_from_peer(S1_ID, (unsigned char*) s2_label_buf, commitment_size * sizeof(block), ENCRYPTED, NULL);
			errors_detected = bytes_in != commitment_size * sizeof(block);

			if (computing_offline)
			{
				timer->process_timestamp(true, verbose, "Done receiving commitment labels from S1\n\n");
				tot_bytes_in += bytes_in;
			}

			if (errors_detected)
			{
				printf("Error receiving commitment labels from S1\n");
			}
		}

		block *extracted_labels = (block*) malloc(gc_input_size * sizeof(block));

		//copy garbled table from recv buffer
		memcpy(&garbledCircuit.garbledTable->table, table_buf, gtable_size * sizeof(block));
		//copy commitment labels to end of buffer, leaving space for labels via OT
		if (chosen_tm == MALICIOUS)
			memcpy(&extracted_labels[num_OT_bits], s2_label_buf, commitment_size * sizeof(block));

		if (!computing_online)
		{
			free(table_buf);
			free(extracted_labels);
			free(s2_label_buf);
			removeGarbledCircuit(&garbledCircuit);
			goto finalization;
		}

		//NOTE synchronization
		peer_net->send_to_peer(S1_ID, ack_buf, 1, PLAINTEXT, NULL);
		peer_net->receive_from_peer(S1_ID, ack_buf, 1, PLAINTEXT, NULL);

		BYTE verify_success, verify_failure;
		BYTE *elln_buf = (BYTE*) malloc(1 + ((2 + chosen_tm) * sizeof(block)));

		if (!computing_offline)
		{
			//NOTE test run timer starts now; offline time NOT included
			timer->process_timestamp(false, verbose, NULL);
			//NOTE test run timer starts now; offline time NOT included
		}

		unsigned char bhat2_buf[num_input_bytes];

		timer->process_timestamp(true, verbose, "\nReceiving XOR share from C\n");
		bytes_in = peer_net->receive_from_peer(C_ID, bhat2_buf, num_input_bytes, ENCRYPTED, NULL);
		timer->process_timestamp(true, verbose, "Done receiving XOR share from C\n\n");
		errors_detected = bytes_in != num_input_bytes;
		tot_bytes_in += bytes_in;

		if (errors_detected)
		{
			printf("Error receiving XOR share from C\n");
		}

		//S2 input bits for OT
		CBitVector *OT_bits = new CBitVector();
		//NOTE passing crypt causes population of OT_bits with random values, implicitly choosing random B2 at runtime
		OT_bits->Create(num_OT_bits, crypt);
		if (chosen_df == HD)
			OT_bits->XORBits(bhat2_buf, 0, num_input_bits);
		else
			OT_bits->SetBits(bhat2_buf, num_input_bits, num_input_bits);

		//receive buffer for OT
		CBitVector *OT_recv_buf = new CBitVector();
		OT_recv_buf->Create(num_OT_bits, 8 * sizeof(block));

		timer->process_timestamp(true, verbose, "\nEngaging in OT with S1\n");
		errors_detected = !OTRecv(OT_recv_buf, OT_bits, num_OT_bits, 8 * sizeof(block), crypt, glock, OT_socket);
		timer->process_timestamp(true, verbose, "Done engaging in OT with S1\n\n");

		if (!errors_detected)
		{
			OT_recv_buf->GetBits((BYTE*) extracted_labels, 0, num_OT_bits * 8 * sizeof(block));

			timer->process_timestamp(true, verbose, "\nEvaluating GC\n");
			evaluate(&garbledCircuit, extracted_labels, (block*) elln_buf);
			timer->process_timestamp(true, verbose, "Done evaluating GC\n\n");
		}
		else
		{
			printf("Could not evaluate GC due to previous errors\n");
		}

		free(extracted_labels);
		free(s2_label_buf);
		free(table_buf);
		OT_recv_buf->delCBitVector();
		OT_bits->delCBitVector();
		delete OT_recv_buf;
		delete OT_bits;

		//mpz_clear(b_2);

		elln_buf[(2 + chosen_tm) * sizeof(block)] = !errors_detected;

		timer->process_timestamp(true, verbose, "\nSending output labels to S1\n");
		bytes_out = peer_net->send_to_peer(S1_ID, elln_buf, 1 + ((2 + chosen_tm) * sizeof(block)), ENCRYPTED, NULL);
		timer->process_timestamp(true, verbose, "Done sending output labels to S1\n\n");
		errors_detected = bytes_out != 1 + ((2 + chosen_tm) * sizeof(block));
		tot_bytes_out += bytes_out;

		if (errors_detected)
		{
			printf("Error sending labels to S1\n");
		}

		//std::cout << "S2 Done\n";

		//mpz_clear(b_2):
		removeGarbledCircuit(&garbledCircuit);
		free(elln_buf);
	}

	else if (my_id == C_ID)
	{
		group_ACK();

		if (!computing_online)
		{
			goto finalization;
		}

		//NOTE synchronization
		peer_net->send_to_peer(S1_ID, ack_buf, 1, PLAINTEXT, NULL);
		peer_net->receive_from_peer(S1_ID, ack_buf, 1, PLAINTEXT, NULL);

		//NOTE test run timer starts now
		timer->process_timestamp(false, verbose, NULL);
		//NOTE test run timer starts now

		/* Generate Random Biometric */

		srand(time(NULL));
		int bits_in_sysrand = lg_flr(RAND_MAX);

		//IEEE 754 mantissa: 23 value bits, one sign bit
		mpf_set_default_prec(24);
		int mantissa_expansion = 23 - bits_in_sysrand;
		double mantissa_exp_factor = (double) (1 << mantissa_expansion) - 1;

		mpf_t b_hat_raw[num_inputs];
		for (int i = 0; i < num_inputs; i++)
		{
			mpf_init(b_hat_raw[i]);
			double bhat_rand =  ((double) rand() / (double) (RAND_MAX)) - 0.5;
			bhat_rand *= mantissa_exp_factor;
			mpf_init_set_d(b_hat_raw[i], bhat_rand);
		}

		mpz_t b_hat;

		/* Compress Biometric If Necessary */

		//NOTE uncompressed biometric feature values (i.e. *_raw_* variables) are generated as floats as per specification

		if (input_length < DEFAULT_BIOMETRIC_INPUT_LENGTH)
		{	//then compress
			mpf_t bhat_min;
			mpf_t bhat_max;
			mpf_init_set(bhat_min, b_hat_raw[0]);
			mpf_init_set(bhat_max, b_hat_raw[0]);
			for (int i = 1; i < num_inputs; i++)
			{	//get min and max vector elements
				if (mpf_cmp(b_hat_raw[i], bhat_min) < 0)
				{
					mpf_set(bhat_min, b_hat_raw[i]);
				}
				else if (mpf_cmp(b_hat_raw[i], bhat_max) > 0)
				{
					mpf_set(bhat_max, b_hat_raw[i]);
				}
			}

			mpf_t range;
			mpf_t delta;
			mpf_t compr_float;
			mpf_t scaling_factor;
			mpf_t compr_max_float;
			mpf_init(range);
			mpf_init(delta);
			mpf_init(compr_float);
			mpf_init(scaling_factor);
			mpf_init_set_ui(compr_max_float, (unsigned long) (1 << COMPRESSED_BIOMETRIC_INPUT_LENGTH) - 1);

			mpf_sub(range, bhat_max, bhat_min);
			mpf_div(scaling_factor, compr_max_float, range);

			mpz_t compr_uint;
			mpz_init2(compr_uint, num_inputs * COMPRESSED_BIOMETRIC_INPUT_LENGTH);
			mpz_init2(b_hat, num_inputs * COMPRESSED_BIOMETRIC_INPUT_LENGTH);
			mpz_set_ui(b_hat, 0);

			uint32_t compr_shift = 0;
			for (int i = 0; i < num_inputs; i++)
			{
				mpf_sub(delta, b_hat_raw[i], bhat_min);
				mpf_mul(compr_float, delta, scaling_factor);
				//cast to uint
				mpz_set_ui(compr_uint, mpf_get_ui(compr_float));
				//left shift and mask
				mpz_mul_2exp(compr_uint, compr_uint, compr_shift);
				mpz_ior(b_hat, b_hat, compr_uint);
				compr_shift += COMPRESSED_BIOMETRIC_INPUT_LENGTH;
			}

			mpf_clear(bhat_min);
			mpf_clear(bhat_max);
			mpf_clear(range);
			mpf_clear(delta);
			mpf_clear(compr_float);
			mpf_clear(scaling_factor);
			mpf_clear(compr_max_float);
			mpz_clear(compr_uint);

		}
		else
		{	//then no compression
			mpz_init2(b_hat, num_inputs * DEFAULT_BIOMETRIC_INPUT_LENGTH);

			mpz_t compr_uint;
			mpz_init2(compr_uint, num_inputs * DEFAULT_BIOMETRIC_INPUT_LENGTH);
			mpz_init2(b_hat, num_inputs * DEFAULT_BIOMETRIC_INPUT_LENGTH);
			mpz_set_ui(b_hat, 0);

			uint32_t compr_shift = 0;
			for (int i = 0; i < num_inputs; i++)
			{
				mpz_set_ui(compr_uint, mpf_get_ui(b_hat_raw[i]));
				mpz_mul_2exp(compr_uint, compr_uint, compr_shift);
				mpz_ior(b_hat, b_hat, compr_uint);
				compr_shift += DEFAULT_BIOMETRIC_INPUT_LENGTH;
			}

			mpz_clear(compr_uint);
		}

		for (int i = 0; i < num_inputs; i++)
		{
			mpf_clear(b_hat_raw[i]);
		}

		//printf("1\n");

		mpz_t r, r_hat;
		mpz_init2(r, num_input_bits);
		mpz_init2(r_hat, num_input_bits);

		gmp_randstate_t state;
		gmp_randinit_mt(state);
		mpz_urandomb(r, state, num_input_bits);
		mpz_xor(r_hat, b_hat, r);

		size_t bytes_exported;
		unsigned char bhat2_buf[num_input_bytes];
		unsigned char bhat1_buf[num_input_bytes];
		mpz_export(bhat2_buf, &bytes_exported, -1, 1, 0, 0, r);
		//assert(bytes_exported == num_input_bytes);
		mpz_export(bhat1_buf, &bytes_exported, -1, 1, 0, 0, r_hat);
		//assert(bytes_exported == num_input_bytes);

		mpz_clear(b_hat);
		mpz_clear(r_hat);
		mpz_clear(r);

		//print_block((block *) bhat2_buf, 1);

		timer->process_timestamp(true, verbose, "\nSending input XOR share to S1\n");
		bytes_out = peer_net->send_to_peer(S1_ID, bhat1_buf, num_input_bytes, ENCRYPTED, NULL);
		timer->process_timestamp(true, verbose, "Done sending input XOR share to S1\n\n");
		errors_detected = bytes_out != num_input_bytes;
		tot_bytes_out += bytes_out;

		if (errors_detected)
		{
			printf("Error sending input XOR share to S1\n");
		}

		timer->process_timestamp(true, verbose, "\nSending input XOR share to S2\n");
		bytes_out = peer_net->send_to_peer(S2_ID, bhat2_buf, num_input_bytes, ENCRYPTED, NULL);
		timer->process_timestamp(true, verbose, "Done sending input XOR share to S2\n\n");
		errors_detected = bytes_out != num_input_bytes;
		tot_bytes_out += bytes_out;

		if (errors_detected)
		{
			printf("Error sending input XOR share to S2\n");
		}

		timer->process_timestamp(true, verbose, "\nReceiving decision from S1\n");
		bytes_in = peer_net->receive_from_peer(S1_ID, &decision, 1, ENCRYPTED, NULL);
		timer->process_timestamp(true, verbose, "Done receiving decision from S1\n\n");
		errors_detected = bytes_in != 1;
		tot_bytes_in += bytes_in;

		if (errors_detected)
		{
			printf("Error receiving decision from S1\n");
		}
		else if (verbose)
		{
			printf("\nDecision at C:\t%u\n\n", decision);
		}
	}

//NOTE label
finalization:

	if (test_run_num == 0)
	{
		std::ofstream comm_results_file;
		comm_results_file.open(comm_res_fname, std::ios::app);

		if (my_id != C_ID)
		{
			comm_results_file << "OT bytes sent:\t\t" << OT_socket->getSndCnt() << " bytes" << std::endl;
			comm_results_file << "OT bytes received:\t\t" << OT_socket->getRcvCnt() <<" bytes" << std::endl;

			comm_results_file << "Other bytes sent:\t\t" << tot_bytes_out << " bytes" << std::endl;
			comm_results_file << "Other bytes received:\t\t" << tot_bytes_in << " bytes" << std::endl;

			comm_results_file << "Total bytes sent:\t\t" << tot_bytes_out + OT_socket->getSndCnt() << " bytes" << std::endl;
			comm_results_file << "Total bytes received:\t\t" << tot_bytes_in + OT_socket->getRcvCnt() << " bytes" << std::endl;
		}
		else
		{
			comm_results_file << "Total bytes sent:\t\t" << tot_bytes_out << " bytes" << std::endl;
			comm_results_file << "Total bytes received:\t\t" << tot_bytes_in << " bytes" << std::endl;
		}

		comm_results_file << "\n";
		comm_results_file.close();
	}

	timer->process_results(id_str[my_id], test_params, test_run_num);


	Cleanup();
	delete crypt;
	delete glock;
	delete timer;

	return EXIT_SUCCESS;
}




