
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


#include "PeerNet.h"


PeerNet::PeerNet(int num_peers_in, int my_id_in, std::string& rsa_prv_keyfile_in, std::string& config_file_in)

: num_peers(num_peers_in), my_id(my_id_in), rsa_prv_keyfile(rsa_prv_keyfile_in), config_file(config_file_in)

{
	initialize_peernet();
}


PeerNet::PeerNet(int num_peers_in, int my_id_in, std::string& rsa_prv_keyfile_in, std::string& config_file_in, int base_port_in)

: num_peers(num_peers_in), my_id(my_id_in), rsa_prv_keyfile(rsa_prv_keyfile_in), config_file(config_file_in), base_port(base_port_in)

{
	initialize_peernet();
}


PeerNet::PeerNet(int num_peers_in, int my_id_in, std::string& rsa_prv_keyfile_in, std::string& config_file_in, int bcr_limit_in, int bcr_delay_in)

: num_peers(num_peers_in), my_id(my_id_in), rsa_prv_keyfile(rsa_prv_keyfile_in), config_file(config_file_in), base_conn_retry_limit(bcr_limit_in), base_conn_retry_delay(bcr_delay_in)

{
	initialize_peernet();
}




PeerNet::~PeerNet()

{
	delete timer;
	for (int peer_id = 0; peer_id < num_peers; peer_id++)
	{
		if (peer_id == my_id)
		{
			RSA_free(peers_[my_id].rsa_prv_key);
		}
		else
		{
			close(peers_[peer_id].sock_fd);
			RSA_free(peers_[peer_id].rsa_pub_key);
			EVP_CIPHER_CTX_free(peers_[peer_id].aes_enc_ctx);
			EVP_CIPHER_CTX_free(peers_[peer_id].aes_dec_ctx);
		}
	}
	free(SEND_TO_ALL_);
	free(RECEIVE_FROM_ALL_);
	free(ALL_SEND_AND_RECEIVE_);
	free(PASS_LEFT_);
	free(PASS_RIGHT_);
}



int PeerNet::load_config()
{
	SEND_TO_ALL_ = (int*) malloc(num_peers * sizeof(int));
	RECEIVE_FROM_ALL_ = (int*) malloc(num_peers * sizeof(int));
	ALL_SEND_AND_RECEIVE_ = (int*) malloc(num_peers * sizeof(int));
	PASS_LEFT_ = (int*) malloc(num_peers * sizeof(int));
	PASS_RIGHT_ = (int*) malloc(num_peers * sizeof(int));

	for (int peer_id = 0; peer_id < num_peers; peer_id++)
	{
		peers_.push_back(peer_identity());
#if OPENSSL_VERSION_NUMBER < V110
		peers_.back().aes_enc_ctx = &peers_.back().enc;
		peers_.back().aes_dec_ctx = &peers_.back().dec;
#endif
		PASS_LEFT_[peer_id] = LEFT_NEIGHBOR(peer_id);
		PASS_RIGHT_[peer_id] = RIGHT_NEIGHBOR(peer_id);
		if (peer_id == my_id)
		{
			SEND_TO_ALL_[peer_id] = ALL_PEERS - ME;
			RECEIVE_FROM_ALL_[peer_id] = 0;
			ALL_SEND_AND_RECEIVE_[peer_id] = ALL_PEERS - ME;
		}
		else
		{
			SEND_TO_ALL_[peer_id] = 0;
			RECEIVE_FROM_ALL_[peer_id] = ME;
			ALL_SEND_AND_RECEIVE_[peer_id] = ALL_PEERS - PEER;
		}
	}

	//default config
	if ((base_conn_retry_limit == 0) || (base_conn_retry_delay == 0))
	{
		base_conn_retry_limit = 8 * num_peers * num_peers;
		base_conn_retry_delay = num_peers;	//in seconds
	}
	reset_conn_retry_delay();

	if ((base_port < 1024) || (base_port > 65535))
		base_port = PN_DEFAULT_BASE_PORT;

	std::ifstream peer_config_file;
	peer_config_file.open(config_file);
	if (!peer_config_file.is_open())
	{
		return 0;
	}
	else
	{
		std::string line;
		int line_count = 0;
		while (getline(peer_config_file, line))
		{
			std::string substring;
			std::vector<std::string> substrings;
			std::stringstream tokenizer(line);

			while (getline(tokenizer, substring, ','))
				substrings.push_back(substring);

			if (substrings.size() != PN_CONFIG_FILE_ELEM_COUNT)
			{
				return 0;
			}

			int peer_id = (int) std::stoi(substrings[0]);
			if (peer_id < num_peers)
			{
				line_count++;
				peers_[peer_id].ip_addr = substrings[1];
				peers_[peer_id].port = std::stoi(substrings[2]);
				if ((peers_[peer_id].port < 1024) || (peers_[peer_id].port > 65535))
					peers_[peer_id].port = base_port + peer_id;
				if (peer_id == my_id)
					peers_[peer_id].rsa_key_fname = rsa_prv_keyfile;
				else
					peers_[peer_id].rsa_key_fname = substrings[3];
			}
		}
		peer_config_file.close();

		if (line_count < num_peers)
		{
			std::cout << "Some peers_ are unaccounted for in the configuration file\n";
			return 0;
		}

		return 1;
	}
}



void PeerNet::initialize_peernet()
{
	timer = new Timer();
	reset_timeout(&conn_retry_timeout, &ref_timeslice, (double) 2304);
	reset_timeout(&flush_read_timeout, &ref_timeslice, (double) 96);

	is_connected_ = load_config() ? init_sockets() : false;

	if (is_connected_)
	{
		//printf("Peer %i connected\n", my_id);
		multicast_ack(PASS_RIGHT_, 1);
	}
	else
		fprintf(stderr, "Could not initialize Peer Net\n");
}



void PeerNet::reset_conn_retry_delay()
{
	conn_retry_delay = {1, 0};
	timer->get_const_product((Timer::timestruct*) &conn_retry_delay, (double) base_conn_retry_delay / conn_retry_factor, true, true);
}



void PeerNet::reset_timeout(timespec* dest_timer, timespec* ref_timer, double factor)
{
	timer->copy((Timer::timestruct*) dest_timer, (Timer::timestruct*) ref_timer);
	timer->get_const_product((Timer::timestruct*) dest_timer, factor, true, true);
}



int PeerNet::aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int ptext_len, unsigned char *ciphertext)
{
	int ctext_len = ptext_len + AES_BLOCK_SIZE;
	int final_len = 0;
	unsigned char *ctext_buf = (unsigned char*) malloc(ctext_len * sizeof(unsigned char));

	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_EncryptUpdate(e,ctext_buf, &ctext_len, plaintext, ptext_len);
	EVP_EncryptFinal_ex(e, ctext_buf + ctext_len, &final_len);
	int out_len = ctext_len + final_len;

	memcpy(ciphertext, ctext_buf, out_len);
	free(ctext_buf);

	return out_len;
}



int PeerNet::aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int ctext_len, unsigned char *plaintext)
{
	int ptext_len = ctext_len;
	int final_len = 0;
	unsigned char *ptext_buf = (unsigned char*) malloc((ctext_len + AES_BLOCK_SIZE)  * sizeof(unsigned char));

	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, ptext_buf, &ptext_len, ciphertext, ctext_len);
	EVP_DecryptFinal_ex(e, ptext_buf + ptext_len, &final_len);
	int out_len = ptext_len  + final_len;

	memcpy(plaintext, ptext_buf, out_len);
	free(ptext_buf);

	return out_len;
}


// send need not block, though timespec is provided for optional synchronization purposes
int PeerNet::send_to_peer(int peer_id, unsigned char *send_buf, int sndbuf_size, int transmit_mode, timespec *tsp_in)
{
	int round_bytes_out = 0;
	int cipher_bytes_out = 0;
	int expected_cipher_bytes_out = AES_BLOCK_SIZE * (1 + (sndbuf_size / AES_BLOCK_SIZE));
	int bytes_to_send = transmit_mode == ENCRYPTED ? expected_cipher_bytes_out : sndbuf_size;
	int timeout_occurred = 0;
	unsigned char *ciphertext;

	//NOTE the behavior of pselect is to not modify the passed timespec
	//NOTE keeping a local copy of tsp_in maintains this behavior for this function
	timespec tsp_local;
	timespec *tsp;
	if (tsp_in == NULL)
		tsp = NULL;
	else
	{
		tsp = &tsp_local;
		timer->copy((Timer::timestruct*) tsp, (Timer::timestruct*) tsp_in);
	}

	try
	{
		if (transmit_mode  == ENCRYPTED)
		{
			ciphertext = (unsigned char*) malloc(expected_cipher_bytes_out * sizeof(unsigned char));
			cipher_bytes_out = aes_encrypt(peers_[peer_id].aes_enc_ctx, send_buf, sndbuf_size, ciphertext);
			if(cipher_bytes_out != expected_cipher_bytes_out)
			{
				std::cerr << "Message encryption error\n";
				free(ciphertext);
				return -1;
			}
		}

		unsigned char* snd_head = transmit_mode == ENCRYPTED ? ciphertext : send_buf;

		timer->timestamp();
		while(!timeout_occurred & (bytes_to_send > 0))
		{
			round_bytes_out = send(peers_[peer_id].sock_fd, snd_head, bytes_to_send, 0);
			bytes_to_send -= round_bytes_out;
			snd_head += round_bytes_out;
			if (tsp != NULL)
			{
				timer->update((struct Timer::timestruct*) tsp, NULL, true);
				timeout_occurred = tsp->tv_sec < 0;
			}
		}

		if (transmit_mode == ENCRYPTED)
			free(ciphertext);

	}
	catch(std::exception& e)
	{
		std::cout << "An exception (in secure_send) was caught: " << e.what() << "\n";
		return -1;
	}

	send_count_ += sndbuf_size - bytes_to_send;
	return timeout_occurred ? 0 : sndbuf_size - bytes_to_send;
}



int PeerNet::receive_from_peer(int peer_id, unsigned char *rcv_buf, int rcvbuf_size, int transmit_mode, timespec *tsp_in)
{
	int round_bytes_in = 0;
	int plain_bytes_in = 0;
	int expected_cipher_bytes_in = AES_BLOCK_SIZE * (1 + (rcvbuf_size / AES_BLOCK_SIZE));
	int bytes_to_receive = transmit_mode == ENCRYPTED ? expected_cipher_bytes_in : rcvbuf_size;
	int timeout_occurred = 0;
	unsigned char *ciphertext;
	fd_set readfds;

	//NOTE the behavior of pselect is to not modify the passed timespec
	//NOTE keeping a local copy of tsp_in maintains this behavior for this function
	timespec tsp_local;
	timespec *tsp;
	if (tsp_in == NULL)
		tsp = NULL;
	else
	{
		tsp = &tsp_local;
		timer->copy((Timer::timestruct*) tsp, (Timer::timestruct*) tsp_in);
	}

	try
	{
		if (transmit_mode == ENCRYPTED)
			ciphertext = (unsigned char*) malloc(2 * bytes_to_receive * sizeof(unsigned char));
		unsigned char *plaintext = (unsigned char*) malloc(bytes_to_receive * sizeof(unsigned char));
		unsigned char *rcv_head = transmit_mode == ENCRYPTED ? ciphertext : plaintext;

		timer->timestamp();
		while(!timeout_occurred & (bytes_to_receive > 0))
		{
			memcpy(&readfds, &peers_[peer_id].fds, sizeof(peers_[peer_id].fds));
			int num_fds = pselect(maxfdp1, &readfds, NULL, NULL, tsp, NULL);
			if (FD_ISSET(peers_[peer_id].sock_fd, &readfds))
			{
				round_bytes_in = recv(peers_[peer_id].sock_fd, rcv_head, bytes_to_receive, 0);
			}
			bytes_to_receive -= round_bytes_in;
			rcv_head += round_bytes_in;
			timeout_occurred = num_fds == 0;
			if (tsp != NULL)
			{
				timer->update((struct Timer::timestruct*) tsp, NULL, true);
				timeout_occurred |= (long) tsp->tv_sec < 0;
			}
		}

		if (transmit_mode == ENCRYPTED)
		{
			plain_bytes_in = aes_decrypt(peers_[peer_id].aes_dec_ctx, ciphertext, expected_cipher_bytes_in, plaintext);
			free(ciphertext);

			if(plain_bytes_in != rcvbuf_size)
			{
				std::cerr << "Message corruption detected from " << peer_id << "\n";
				free(plaintext);
				return -1;
			}
		}

		memcpy(rcv_buf, plaintext, rcvbuf_size);
		free(plaintext);

		if (bytes_to_receive < 0)
		{
			std::cerr << "Message overflow detected from " << peer_id << "\n";
			return -1;
		}

	}
	catch(std::exception& e)
	{
		std::cerr << "An exception (in secure_receive) was caught: " << e.what() << "\n";
		return -1;
	}

	recv_count_ += rcvbuf_size - bytes_to_receive;
	return timeout_occurred ? 0 : rcvbuf_size - bytes_to_receive;
}




//TODO mpz versions/wrapper of {send, receive, multicast}
//mpz_import(data[i], unit_size, -1, 1, -1, 0, decrypted);
//mpz_export(pointer, NULL, -1, 1, -1, 0, data[i]);


//NOTE participant roster is expected to be an array of int of length num_parties
//NOTE entry i has bit j set if and only if peer i is sending data to peer j
//NOTE sends data in one round using pattern from https://en.wikipedia.org/wiki/All-to-all_(parallel_pattern)
//NOTE parties then act as servers t receive data first-com-first-served
//NOTE benefits from starting peers in ascending order by id in situations where many multicasts are called
//NOTE 	and communication dominates local computation
//TODO tweak initial connection parameters to allow parties to connect in any order
// send_mode in {SEND_ONE_MSG_TO_ALL, SEND_DISTINCT_MESSAGES}
// receipt_mode in {UNIFORM_RECEIPT_SIZE, VARIABLE_RECEIPT_SIZE}
// transmit_mode in {PLAINTEXT, ENCRYPTED}

int PeerNet::multicast(int *participant_roster, int* send_size, int* recv_size, unsigned char** send_buf, unsigned char** recv_buf, int send_mode, int receipt_mode, int transmit_mode)
{
	int errors = 0;
	int bytes_sent = 0;
	int bytes_received = 0;
	int this_send_size = send_size[0];
	unsigned char *sendbuf_ptr = send_buf[0];

	for (int peer = 0; peer < num_peers - 1 + (num_peers % 2); peer++)
	{
		int peer_id, end_peer;
		if (num_peers % 2)
		{
			peer_id = (peer - my_id) % num_peers;
			if (peer_id < 0)
				peer_id += num_peers;
		}
		else
		{
			end_peer = (peer * num_peers / 2) % (num_peers - 1);
			if (my_id == num_peers - 1)
				peer_id = end_peer;
			else if (my_id == end_peer)
				peer_id = num_peers - 1;
			else
				peer_id = (peer - my_id) % (num_peers - 1);
			if (peer_id < 0)
				peer_id += num_peers - 1;
		}
		if (my_id == peer_id) continue;

		if (send_mode == SEND_DISTINCT_MESSAGES)
		{
			sendbuf_ptr = send_buf[peer_id];
			this_send_size = send_size[peer_id];
		}
		if (participant_roster[my_id] & PEER)
		{
			bytes_sent = send_to_peer(peer_id, sendbuf_ptr, this_send_size, transmit_mode, NULL);
			errors += bytes_sent != this_send_size;
			//printf("%i bytes sent from %i to %i\n", bytes_sent, my_id, peer_id);
		}
	}

	fd_set masterfds, roundfds;
	memcpy(&masterfds, &peerfds_, sizeof(peerfds_));

	int local_recv_size[num_peers];
	unsigned char *local_recv_buf_ptr[num_peers];
	unsigned char **local_recv_buf = (unsigned char**) malloc(num_peers * sizeof(unsigned char*));

	int target_receipts = 0;
	for (int peer_id = 0; peer_id < num_peers; peer_id++)
	{
		if (participant_roster[peer_id] & ME)
		{
			target_receipts += PEER;
			if (receipt_mode == VARIABLE_RECEIPT_SIZE)
				local_recv_size[peer_id] = recv_size[peer_id];
			else
				local_recv_size[peer_id] = recv_size[0];
			if (transmit_mode == ENCRYPTED)
			{
				local_recv_size[peer_id] = AES_BLOCK_SIZE * (1 + (local_recv_size[peer_id] / AES_BLOCK_SIZE));
				local_recv_buf[peer_id] = (unsigned char*) malloc(2 * local_recv_size[peer_id] * sizeof(unsigned char));
			}
			else
				local_recv_buf[peer_id] = (unsigned char*) malloc(local_recv_size[peer_id] * sizeof(int));
		}
		else
		{
			local_recv_size[peer_id] = 0;
			local_recv_buf[peer_id] = NULL;
			FD_CLR(peers_[peer_id].sock_fd, &masterfds);
		}
	}

	memcpy(local_recv_buf_ptr, local_recv_buf, num_peers * sizeof(unsigned char*));

	int round_bytes_in = 0;
	int plain_bytes_in = 0;

	while(target_receipts > 0)
	{
		memcpy(&roundfds, &masterfds, sizeof(masterfds));
		int num_fds = pselect(maxfdp1, &roundfds, NULL, NULL, &ref_timeslice, NULL);
		if (num_fds > 0)
		{
			for (int peer_id = 0; peer_id < num_peers; peer_id++)
			{
				if (peer_id == my_id) continue;
				if (FD_ISSET(peers_[peer_id].sock_fd, &roundfds))
				{
					round_bytes_in = recv(peers_[peer_id].sock_fd, local_recv_buf_ptr[peer_id], local_recv_size[peer_id], 0);
					local_recv_size[peer_id] -= round_bytes_in;
					local_recv_buf_ptr[peer_id] += round_bytes_in;
					if (local_recv_size[peer_id] <= 0)
					{
						//printf("Received from peer %i\n", peer_id);
						target_receipts -= PEER;
						FD_CLR(peers_[peer_id].sock_fd, &masterfds);
						int *this_recv_size = &recv_size[receipt_mode == VARIABLE_RECEIPT_SIZE ? peer_id : 0];
						if (transmit_mode == ENCRYPTED)
						{
							int ciphertext_size = AES_BLOCK_SIZE * (1 + (*this_recv_size / AES_BLOCK_SIZE));
							plain_bytes_in = aes_decrypt(peers_[peer_id].aes_dec_ctx, local_recv_buf[peer_id], ciphertext_size, recv_buf[peer_id]);
						}
						else
							memcpy(recv_buf[peer_id], local_recv_buf[peer_id], *this_recv_size);
						errors += local_recv_size[peer_id] < 0;
					}
				}
			}
		}
	}

	for (int peer_id = 0; peer_id < num_peers; peer_id++)
	{
		if (local_recv_buf[peer_id] != NULL)
			free(local_recv_buf[peer_id]);
	}
	free(local_recv_buf);

	//printf("%i errors detected\n", errors);
	return errors;
}




// for synchronization purposes
int PeerNet::multicast_ack(int *participant_roster, int num_rounds)
{
	unsigned char **ack_buf = (unsigned char **) malloc(num_peers * sizeof(unsigned char *));
	for (int peer_id = 0; peer_id < num_peers; peer_id++)
		ack_buf[peer_id] = (unsigned char *) malloc(sizeof(unsigned char));

	int ack_size = sizeof(unsigned char);
	ack_buf[my_id][0] = ACK;

	int errors = 0;
	for (int i = 0; i < num_rounds; i++)
	{
		multicast(participant_roster, &ack_size, &ack_size, &ack_buf[my_id], ack_buf,
				  SEND_ONE_MSG_TO_ALL, UNIFORM_RECEIPT_SIZE, PLAINTEXT);

		for (int peer_id = 0; peer_id < num_peers; peer_id++)
		{
			errors |= ack_buf[peer_id][0] != ACK;
		}
	}

	for (int peer_id = 0; peer_id < num_peers; peer_id++)
	{
		free(ack_buf[peer_id]);
	}
	free(ack_buf);

	return errors;
}



int PeerNet::flush_read_buffer(int peer_id)
{
	int buf_cleared = 0;
	int bytes_received = 0;
	unsigned char flush_buf[PN_FLUSH_BUF_SIZE];
	while (!buf_cleared)
	{
		bytes_received = receive_from_peer(peer_id, flush_buf, PN_FLUSH_BUF_SIZE, PLAINTEXT, &flush_read_timeout);
		buf_cleared = bytes_received == 0;
	}

	return bytes_received;
}



int PeerNet::register_my_socket(int sock_fd)
{
	peers_[my_id].sock_fd = sock_fd;
	FD_SET(sock_fd, &peers_[my_id].fds);
	FD_SET(sock_fd, &peerfds_);
	lastfdp1 = maxfdp1;
	if (peers_[my_id].sock_fd + 1 > maxfdp1)
		maxfdp1 = peers_[my_id].sock_fd + 1;
	return maxfdp1;
}



int PeerNet::unregister_my_socket()
{
	FD_CLR(peers_[my_id].sock_fd, &peers_[my_id].fds);
	FD_CLR(peers_[my_id].sock_fd, &peerfds_);
	peers_[my_id].sock_fd = -1;
	maxfdp1 = lastfdp1;
	return maxfdp1;
}



int PeerNet::get_server_socket(int client_port)
{
	peers_[my_id].sock_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (peers_[my_id].sock_fd < 0){
		printf("Socket initialization failure\n");
		peers_[my_id].sock_fd = -1;
		return 0;
	}

	int one = 1;
	setsockopt(peers_[my_id].sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
	setsockopt(peers_[my_id].sock_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(int));

	int server_port = client_port;
	struct sockaddr_in sa_in;
	sa_in.sin_family = PF_INET;
	sa_in.sin_addr.s_addr = htonl(INADDR_ANY);
	sa_in.sin_port = server_port;
	int alen = sizeof(sa_in);
	struct sockaddr *sa_ptr = (struct sockaddr*) &sa_in;

	int err = bind(peers_[my_id].sock_fd, sa_ptr, alen);
	if (err < 0){
		printf("Could not bind socket\n");
		peers_[my_id].sock_fd = -1;
		close(peers_[my_id].sock_fd);
		return 0;
	}

	err	= listen(peers_[my_id].sock_fd, 2);
	if (err < 0){
		printf("Could not listen on port %d\n", server_port);
		close(peers_[my_id].sock_fd);
		peers_[my_id].sock_fd = -1;
		return 0;
	}

	return 1;
}



int PeerNet::accept_peer(int peer_id)
{
	int err = 0;
	peers_[peer_id].sock_fd = accept(peers_[my_id].sock_fd, NULL, NULL);
	if (peers_[peer_id].sock_fd < 0){
		printf("Could not accept client %i\n", peer_id);
		return 0;
	}
	FD_SET(peers_[peer_id].sock_fd, &peers_[peer_id].fds);
	socklen_t addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in *sa_in = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
	err = getpeername(peers_[peer_id].sock_fd, (struct sockaddr*) sa_in, &addrlen);

	in_addr_t peer_bin_addr;
	err = inet_pton(PF_INET, const_cast<char*>(peers_[peer_id].ip_addr.c_str()), &peer_bin_addr);
	bool ip_mismatch = (err < 0 ) || (peer_bin_addr != sa_in->sin_addr.s_addr);
	free(sa_in);

	int lastfdp1 = maxfdp1;
	if (peers_[peer_id].sock_fd + 1 > maxfdp1)
		maxfdp1 = peers_[peer_id].sock_fd + 1;

	int int_one = 1;
	setsockopt(peers_[peer_id].sock_fd, SOL_SOCKET, SO_REUSEADDR, &int_one, sizeof(int));
	setsockopt(peers_[peer_id].sock_fd, IPPROTO_TCP, TCP_NODELAY, &int_one, sizeof(int));

	int bytes_in = 0;
	unsigned char response_to_client;
	unsigned char peer_id_buf[2];
	unsigned char *reported_id = peer_id_buf;
	unsigned char *reported_num_peers = peer_id_buf + 1;;

	bytes_in = receive_from_peer(peer_id, peer_id_buf, 2, PLAINTEXT, &conn_retry_timeout);
	if (ip_mismatch || (bytes_in <= 0) || (*reported_id != peer_id) || (*reported_num_peers != num_peers))
	{
		response_to_client = 0;
		send_to_peer(peer_id, &response_to_client, 1, PLAINTEXT, &conn_retry_timeout);
		pselect(maxfdp1, NULL, NULL, NULL, &conn_retry_timeout, NULL);
		close(peers_[peer_id].sock_fd);
		maxfdp1 = lastfdp1;
	}
	else
	{
		response_to_client = 1;
		send_to_peer(peer_id, &response_to_client, 1, PLAINTEXT, &conn_retry_timeout);
		FD_SET(peers_[peer_id].sock_fd, &peerfds_);
	}

	return response_to_client;
}



int PeerNet::client_connect(int peer_id, char* server_addr)
{
	peers_[peer_id].sock_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (peers_[peer_id].sock_fd < 0){
		//printf("Socket initialization failure\n");
		return 0;
	}
	FD_SET(peers_[peer_id].sock_fd, &peers_[peer_id].fds);

	struct sockaddr_in sa_in;
	in_addr_t saddr_bin;
	int err = inet_pton(PF_INET, server_addr, &saddr_bin);
	sa_in.sin_addr.s_addr = saddr_bin;
	sa_in.sin_family = PF_INET;
	sa_in.sin_port = peers_[my_id].port;
	int alen = sizeof(sa_in);
	struct sockaddr *sa_ptr = (struct sockaddr*) &sa_in;

	err = connect(peers_[peer_id].sock_fd, sa_ptr, alen);
	if (err < 0){
		//printf("Could not connect to server %i\n", peer_id);
		return 0;
	}
	int lastfdp1 = maxfdp1;
	if (peers_[peer_id].sock_fd + 1 > maxfdp1)
		maxfdp1 = peers_[peer_id].sock_fd + 1;

	int one = 1;
	setsockopt(peers_[peer_id].sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
	setsockopt(peers_[peer_id].sock_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(int));

	int bytes_in = 0;
	int bytes_out = 0;
	unsigned char ip_buf[2];
	*ip_buf = (unsigned char) my_id;
	*(ip_buf + 1) = (unsigned char) num_peers;
	unsigned char server_accepts = 0;

	bytes_out = send_to_peer(peer_id, ip_buf, 2, PLAINTEXT, &conn_retry_timeout);
	if (bytes_out > 0)
		bytes_in =  receive_from_peer(peer_id, &server_accepts, 1, PLAINTEXT, &conn_retry_timeout);

	if ((bytes_in <= 0) | !server_accepts)
		maxfdp1 = lastfdp1;
	else
		FD_SET(peers_[peer_id].sock_fd, &peerfds_);

	return server_accepts;
}



int PeerNet::load_peer_identity(int peer_id)
{
	if (peer_id == my_id)
	{	//CAUTION this must be done first for all parties

		peers_[my_id].sock_fd = -1;
		FILE *rsa_prv_key_file = fopen(peers_[my_id].rsa_key_fname.c_str(), "r");
		if(rsa_prv_key_file == NULL)
		{
			printf("File Open %s error\n", peers_[my_id].rsa_key_fname.c_str());
			return 0;
		}
		peers_[my_id].rsa_prv_key = PEM_read_RSAPrivateKey(rsa_prv_key_file, NULL, NULL, NULL);
		if(peers_[my_id].rsa_prv_key == NULL)
		{
			printf("Read Private Key for RSA Error\n");
			return 0;
		}
		peers_[my_id].rsa_pub_key = NULL;
		peers_[my_id].aes_enc_ctx = NULL;
		peers_[my_id].aes_dec_ctx = NULL;
	}
	else
	{	//CAUTION peers_[peer_id].sock must be established prior to calling

		int peer_is_server = peer_id < my_id;
		FILE *rsa_pub_key_file = fopen(peers_[peer_id].rsa_key_fname.c_str(), "r");
		if(rsa_pub_key_file == NULL)
		{
			printf("File Open %s error\n", peers_[peer_id].rsa_key_fname.c_str());
			return 0;
		}
		peers_[peer_id].rsa_pub_key = PEM_read_RSA_PUBKEY(rsa_pub_key_file, NULL, NULL, NULL);
		if(peers_[peer_id].rsa_pub_key == NULL)
		{
			printf("Read Public Key for RSA Error\n");
			return 0;
		}
		peers_[peer_id].aes_enc_ctx = EVP_CIPHER_CTX_new();
		peers_[peer_id].aes_dec_ctx = EVP_CIPHER_CTX_new();
		unsigned char key_out_buf[32];
		unsigned char aes_key[16];
		unsigned char aes_iv[16];

		if (peer_is_server)
		{
			int key_in_size = RSA_size(peers_[my_id].rsa_prv_key);
			unsigned char *key_in_buf = (unsigned char*) malloc(key_in_size * sizeof(unsigned char));
			int bytes_in = receive_from_peer(peer_id, key_in_buf, key_in_size, PLAINTEXT, &conn_retry_timeout);

			if (bytes_in < 0)
			{
				printf("ERROR reading from socket \n");
				free(key_in_buf);
				return 0;
			}
			unsigned char *decrypted_aes_key = (unsigned char*) malloc(bytes_in * sizeof(unsigned char));
			memset(decrypted_aes_key, 0x00, bytes_in);
			int key_len = RSA_private_decrypt(bytes_in, key_in_buf, decrypted_aes_key, peers_[my_id].rsa_prv_key, RSA_PKCS1_OAEP_PADDING);

			if(key_len < 1)
			{
				printf("RSA private decrypt error\n");
				free(decrypted_aes_key);
				free(key_in_buf);
				return 0;
			}

			memcpy(aes_key, decrypted_aes_key, 16);
			memcpy(aes_iv, decrypted_aes_key + 16, 16);
			EVP_CIPHER_CTX_init(peers_[peer_id].aes_enc_ctx);
			EVP_EncryptInit_ex(peers_[peer_id].aes_enc_ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv);
			EVP_CIPHER_CTX_init(peers_[peer_id].aes_dec_ctx);
			EVP_DecryptInit_ex(peers_[peer_id].aes_dec_ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv);

			free(decrypted_aes_key);
			free(key_in_buf);
		}
		else
		{	//I am server
			if (!RAND_status())
			{
				RAND_poll();
				if (!RAND_status())
				{
					printf("Not enough entropy to generate AES session key\n");
					return 0;
				}
			}
			if(!RAND_bytes(key_out_buf, 32))
			{
				printf("AES key, iv generation error\n");
			}

			memcpy(aes_key, key_out_buf, 16);
			memcpy(aes_iv, key_out_buf + 16, 16);
			EVP_CIPHER_CTX_init(peers_[peer_id].aes_enc_ctx);
			EVP_EncryptInit_ex(peers_[peer_id].aes_enc_ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv);
			EVP_CIPHER_CTX_init(peers_[peer_id].aes_dec_ctx);
			EVP_DecryptInit_ex(peers_[peer_id].aes_dec_ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv);

			int key_out_size = RSA_size(peers_[peer_id].rsa_pub_key);
			unsigned char *encrypted_aes_key = (unsigned char*) malloc(key_out_size * sizeof(unsigned char));
			memset(encrypted_aes_key, 0x00, key_out_size);
			int enc_len = RSA_public_encrypt(32, key_out_buf, encrypted_aes_key, peers_[peer_id].rsa_pub_key, RSA_PKCS1_OAEP_PADDING);

			if(enc_len < 1)
			{
				printf("RSA public encrypt error\n");
				free(encrypted_aes_key);
				return 0;
			}
			int bytes_out = send_to_peer(peer_id, encrypted_aes_key, key_out_size, PLAINTEXT, &conn_retry_timeout);

			if (bytes_out < 0)
			{
				printf("ERROR writing to socket \n");
				free(encrypted_aes_key);
				return 0;
			}

			free(encrypted_aes_key);
		}
	}
	return 1;
}



void PeerNet::retry_next()
{
	if (num_conn_tries < base_conn_retry_limit * conn_retry_factor)
	{
		num_conn_tries++;
		pselect(maxfdp1, NULL, NULL, NULL, &conn_retry_delay, NULL);
	}
	else
		retries_remain = false;
}



int PeerNet::serve(int peer_id, int client_port)
{
	FD_ZERO(&peers_[peer_id].fds);
	if (peers_[my_id].sock_fd == -1)
		if (!get_server_socket(client_port)) {retry_next(); return 0;}
	if (!accept_peer(peer_id)) {retry_next(); return 0;}
	if (!load_peer_identity(peer_id)) {retry_next(); return 0;}
	close(peers_[my_id].sock_fd);
	peers_[my_id].sock_fd = -1;
	return 1;
}



int PeerNet::request(int peer_id)
{
	FD_ZERO(&peers_[peer_id].fds);
	char *peer_addr = (char*) const_cast<char*>(peers_[peer_id].ip_addr.c_str());
	if (!client_connect(peer_id, peer_addr)) {retry_next(); return 0;}
	if (!load_peer_identity(peer_id)) {retry_next(); return 0;}
	return 1;
}



int PeerNet::init_sockets()
{
	load_peer_identity(my_id);

	int conns_established = 0;
	int target_conns = ALL_PEERS - ME;

	while (retries_remain & (conns_established != target_conns))
	{
		for (int peer = 0; peer < num_peers - 1 + (num_peers % 2); peer++)
		{
			int peer_id, end_peer;
			if (num_peers % 2)
			{
				peer_id = (peer - my_id) % num_peers;
				while (peer_id < 0)
					peer_id += num_peers;
			}
			else
			{
				end_peer = (peer * num_peers / 2) % (num_peers - 1);
				if (my_id == num_peers - 1)
					peer_id = end_peer;
				else if (my_id == end_peer)
					peer_id = num_peers - 1;
				else
					peer_id = (peer - my_id) % (num_peers - 1);
				while (peer_id < 0)
					peer_id += num_peers - 1;
			}
			if (my_id == peer_id) continue;

			int peer_port = peers_[peer_id].port;
			while (retries_remain & !(conns_established & PEER))
			{
				if (my_id < peer_id)
					conns_established |= (serve(peer_id, peer_port) << peer_id);
				else
					conns_established |= (request(peer_id) << peer_id);
			}
		}
	}

	return conns_established == target_conns;
}






