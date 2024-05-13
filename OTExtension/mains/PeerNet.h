
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


#ifndef _PEER_NET_
#define _PEER_NET_

#include <cstdlib>
#include <cstring>
//#include <cmath>
#include <cassert>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//#include <math.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/tcp.h>

#include "Timer.h"


#define PN_LAST_ID (num_peers - 1)

#define ACK 32
#define PN_SUCCESS 64
#define PN_FAILURE 128

#define PN_FLUSH_BUF_SIZE 512
#define PN_DEFAULT_BASE_PORT 38003
#define PN_CONFIG_FILE_ELEM_COUNT 4

#define SEND_ONE_MSG_TO_ALL 0
#define SEND_DISTINCT_MESSAGES 1

#define UNIFORM_RECEIPT_SIZE 0
#define VARIABLE_RECEIPT_SIZE 1

#define PLAINTEXT 0
#define ENCRYPTED 1

#define V110 (1 << 11) + (1 << 9)

//CAUTION peer_id is not defined globally
#define ME (1 << my_id)
#define PEER (1 << peer_id)
#define ALL_PEERS (1 << num_peers) - 1
#define LEFT_NEIGHBOR(id) (1 << ((id - 1) % num_peers))
#define RIGHT_NEIGHBOR(id) (1 << ((id + 1) % num_peers))



class PeerNet {

public:

	PeerNet(int num_peers_in, int my_id_in, std::string& rsa_prv_keyfile_in, std::string& config_file_in);
	PeerNet(int num_peers_in, int my_id_in, std::string& rsa_prv_keyfile_in, std::string& config_file_in, int base_port_in);
	PeerNet(int num_peers_in, int my_id_in, std::string& rsa_prv_keyfile_in, std::string& config_file_in, int bcr_limit_in, int bcr_delay_in);

	~PeerNet();

	//types


	struct peer_identity {
		int id;
		int sock_fd;
		fd_set fds;
		int port;
		std::string ip_addr;
		std::string rsa_key_fname;
		RSA *rsa_pub_key;
		RSA *rsa_prv_key;
#if OPENSSL_VERSION_NUMBER < V110
		EVP_CIPHER_CTX enc;
		EVP_CIPHER_CTX dec;
#endif
		EVP_CIPHER_CTX *aes_enc_ctx;
		EVP_CIPHER_CTX *aes_dec_ctx;
	};

	//////functions

	//TODO des_sign()
	//TODO des_verify()
	int aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int ptext_len, unsigned char *ciphertext);
	int aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int ctext_len, unsigned char *plaintext);

	int send_to_peer(int peer_id, unsigned char *send_buf, int sndbuf_size, int transmit_mode, timespec *tsp_in);
	int receive_from_peer(int peer_id, unsigned char *rcv_buf, int rcvbuf_size, int transmit_mode, timespec *tsp_in);
	int multicast(int *participant_roster, int* send_size, int* recv_size, unsigned char** send_buf, unsigned char** recv_buf,
				  int send_mode, int receipt_mode, int transmit_mode);

	int multicast_ack(int *participant_roster, int num_rounds);

	int flush_read_buffer(int peer_id);
	int register_my_socket(int sock_fd);
	int unregister_my_socket();

	////read only variables

	const std::vector<peer_identity>& peers() const {return peers_;};
	const fd_set& peerfds() const {return peerfds_;};
	const int& is_connected() const {return is_connected_;};
	const int& send_count() const {return send_count_;};
	const int& recv_count() const {return recv_count_;};

	//multicast preset constant participant rosters
	int* SEND_TO_ALL() const {return SEND_TO_ALL_;};
	int* RECEIVE_FROM_ALL() const {return RECEIVE_FROM_ALL_;};
	int* ALL_SEND_AND_RECEIVE() const {return ALL_SEND_AND_RECEIVE_;};
	int* PASS_LEFT() const {return PASS_LEFT_;};
	int* PASS_RIGHT() const {return PASS_RIGHT_;};


private:

	//////types

	//////functions

	int load_config();
	void initialize_peernet();
	void reset_conn_retry_delay();
	void reset_timeout(timespec* dest_timer, timespec* ref_timer, double factor);
	int client_connect(int peer_id, char* server_addr);
	int get_server_socket(int client_port);
	int accept_peer(int peer_id);
	int load_peer_identity(int peer_id);
	void retry_next();
	int serve(int peer_id, int client_port);
	int request(int peer_id);
	int init_sockets();

	//////variables

	////public read only variables

	std::vector<peer_identity> peers_;
	fd_set peerfds_;
	int is_connected_;
	int send_count_ = 0;
	int recv_count_ = 0;

	//multicast preset constant participant rosters
	int* SEND_TO_ALL_;
	int* RECEIVE_FROM_ALL_;
	int* ALL_SEND_AND_RECEIVE_;
	int* PASS_LEFT_;
	int* PASS_RIGHT_;


	////pure private variables

	int num_peers;
	int my_id;
	Timer *timer;

	//NOTE on initial connection parameters:
	// asymmetrical client-server pattern: parties with lower id act as server more often
	// program will attempt a total of num_conn_tries times to connect between all (num_peers-1) peers
	// each attempt will allow conn_retry_timeout seconds for connection and then wait conn_retry_delay seconds before attempting again
	// default parameters are currently set so that total time attempting to connect is approximately 8*(num_peers^3) seconds
	// low-id peers (i.e. frequent servers) generally delay for a shorter amount of time on retry than high-id peers (i.e frequent clients)
	// initial values are set to zero for now to allow runtime customization and are set to defaults in PeerNet.cpp initialization functions
	// specifically, the current defaults (not set below) are:
	// base_conn_retry_limit = 8 * num_peers * num_peers;
	// base_conn_retry_delay = num_peers;	//in seconds
	// the following runtime bound holds:
	// 0 <= num_conn_tries < base_conn_retry_limit * conn_retry_factor

	int num_conn_tries = 0;
	int retries_remain = true;
	int base_conn_retry_limit = 0;
	int base_conn_retry_delay = 0;
	int conn_retry_factor = 2 * (num_peers + my_id) * (num_peers - my_id);

	// minimum systemwide atomic unit of time
	// min clock nano res tested ~= 15258 nanosec for 3.6Ghz Ryzen5 3600
	// processors with clock speeds below 1.5 Ghz may need to increase ref_timeslice
	timespec ref_timeslice = {0, 32768};
	timespec conn_retry_delay;
	timespec conn_retry_timeout;
	timespec flush_read_timeout;
	int maxfdp1 = 0;
	int lastfdp1 = 0;

	std::string config_file = "pn-config-local";
	std::string rsa_prv_keyfile;

	int base_port = PN_DEFAULT_BASE_PORT;
	int using_unique_ports = false;

};

#endif


