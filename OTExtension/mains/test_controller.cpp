
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


#include "test_controller.h"
#include "PeerNet.h"

#include <string>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <fcntl.h>

#include "parse_options.h"

int my_id;
int test_delay_sec = 2;
int timeout_sec = 8;
int num_test_runs = 10;

int maxfdp1 = 0;
int target_update_value = 0;

int status;
pid_t pid2 = -1;

int num_peers = 3;

PeerNet *peer_net;

unsigned char ack = ACK;

std::string pn_config_file;
std::string rsa_prv_keyfile;



int32_t read_test_options(int32_t *argcp, char ***argvp, int *role, std::string *test_command_std)
{
	int num_test_runs_in = 0;
	bool printhelp = false;

	parsing_ctx options[] =
	{
		{ (void*) role, T_NUM, "r", "Role: 0..num_peers-1", true, false },
		{ (void*) &num_test_runs, T_NUM, "nt", "Number of test runs, default: 10", false, false },
		{ (void*) &num_peers, T_NUM, "np", "Number of peers(), default: 3", false, false },
		{ (void*) test_command_std, T_STR, "c", "Terminal command to test", true, false },
		{ (void*) &pn_config_file, T_STR, "fc", "Peernet config file name", true, false },
		{ (void*) &rsa_prv_keyfile, T_STR, "fr", "RSA private key file name", true, false },
		{ (void*) &timeout_sec, T_NUM, "to", "Timeout in seconds, 0 for no timeout, default: 8 sec", false, false },
		{ (void*) &test_delay_sec, T_NUM, "td", "Time to delay between tests, 0 for no delay, default: 1 sec", false, false },
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

	assert(*role >= 0);
	assert(*role < num_peers);

	if (num_test_runs_in != 0)
	{
		assert(num_test_runs_in > 0);
		num_test_runs = (int) num_test_runs_in;
	}

	return 1;
}



extern "C" {

	void handle_hang(int sig)
	{
		status = HANG;
		fprintf(stderr, "Signal handler killing pid2\n");
		kill(pid2, SIGKILL);
	}


	void notify_peers()
	{
		for (int peer_id = 0; peer_id < num_peers; peer_id++)
		{
			if (peer_id != my_id)
				peer_net->send_to_peer(peer_id, (unsigned char*) &status, sizeof(int), PLAINTEXT, NULL);
		}
	}


	int run_test(int test_num, char **test_args)
	{
		pid_t pid1;
		int aggregate_status = 0;

		struct sigaction su1act;
		su1act.sa_handler = handle_hang;
		sigemptyset(&su1act.sa_mask);
		su1act.sa_flags = SA_INTERRUPT;
		sigaction(SIGUSR1, &su1act, NULL);

		int pipe_conn[2];
		if (pipe(pipe_conn) < 0)
		{
			status = FAIL;
			fprintf(stderr, "Test %i: Could not set up pipe connection\n", test_num);
			notify_peers();
			return FAIL;
		}

		if ((pid1 = fork())  < 0)
		{
			status = FAIL;
			fprintf(stderr, "Test %i: Could not fork main process\n", test_num);
			notify_peers();
			close(pipe_conn[PIPE_READ]);
			close(pipe_conn[PIPE_WRITE]);
			return FAIL;
		}
		if (pid1 == 0)
		{
			close(pipe_conn[PIPE_READ]);
			if ((pid2 = fork())  < 0)
			{
				fprintf(stderr, "Test %i: Could not fork child process\n", test_num);
				aggregate_status = FAIL;
			}
			if (pid2 == 0)
			{	//youngest child process
				execvp(test_args[0], &test_args[0]);
				fprintf(stderr, "Test %i: Could not execute supplied command\n", test_num);
				status = NO_EXEC;
				notify_peers();
				exit(NO_EXEC);
			}
			else
			{	//oldest child process
				status = FAIL;
				if (aggregate_status != FAIL)
				{
					wait(&status);
				}
				if (status != HANG)
				{
					//fprintf(stderr, "Notifying parent of status\n");
					write(pipe_conn[PIPE_WRITE], (unsigned char*) &status, sizeof(int));
				}
				close(pipe_conn[PIPE_WRITE]);
				notify_peers();
				exit(0);
			}
		}
		else
		{	//parent process
			timeval tv_timeout;
			timeval *timeout_ptr;
			if (timeout_sec <= 0)
				timeout_ptr = NULL;
			else
			{
				tv_timeout.tv_sec = timeout_sec;
				tv_timeout.tv_usec = 0;
				timeout_ptr = &tv_timeout;
			}

			fd_set peerfds, readfds;
			int reported_status;
			int update_value = 0;
			status = PASS;

			close(pipe_conn[PIPE_WRITE]);
			maxfdp1 = peer_net->register_my_socket(pipe_conn[PIPE_READ]);
			fd_set pn_peerfds = peer_net->peerfds();
			memcpy(&peerfds, &pn_peerfds, sizeof(pn_peerfds));

			while (update_value != target_update_value)
			{
				memcpy(&readfds, &peerfds, sizeof(peerfds));
				int num_fds = select(maxfdp1, &readfds, NULL, NULL, timeout_ptr);
				if (num_fds > 0)
				{
					for (int peer_id = 0; peer_id < num_peers; peer_id++)
					{
						int already_updated = update_value & (1 << peer_id);
						if (!already_updated && FD_ISSET(peer_net->peers()[peer_id].sock_fd, &readfds))
						{
							if (peer_id == my_id)
							{
								read(pipe_conn[PIPE_READ], (unsigned char *) &reported_status, sizeof(int));
								if (reported_status != PASS && reported_status != ACK)
									fprintf(stderr, "Child process reports status %i\n", reported_status);
								close(pipe_conn[PIPE_READ]);
								FD_CLR(pipe_conn[PIPE_READ], &peerfds);
							}
							else
							{
								peer_net->receive_from_peer(peer_id, (unsigned char*) &reported_status, sizeof(int), PLAINTEXT, NULL);
								if (reported_status != PASS && reported_status != ACK)
									fprintf(stderr, "Peer %i reports status %i\n", peer_id, reported_status);
								FD_CLR(peer_net->peers()[peer_id].sock_fd, &peerfds);
							}
							aggregate_status |= reported_status;
							update_value |= (1 << peer_id);
						}
					}
				}
				else if (num_fds == 0)
				{//timeout
					if (!(update_value & (1 << my_id)))
					{	//child process timeout
						status = HANG;
						aggregate_status |= HANG;
						kill(pid1, SIGUSR1);
						waitpid(pid1, NULL, 0);
						close(pipe_conn[PIPE_READ]);
						FD_CLR(pipe_conn[PIPE_READ], &peerfds);
						update_value |= (1 << my_id);
						if (reported_status != PASS)
							fprintf(stderr, "Child process timeout\n");
						notify_peers();
					}
				}
				else
				{
					fprintf(stderr, "Select error\n");
				}
			}

			maxfdp1 = peer_net->unregister_my_socket();

			//fprintf(stderr, "Status: %i\n", status);
			//fprintf(stderr, "Aggregate Status: %i\n", aggregate_status);

			return aggregate_status;
		}
	}

}	//end extern "C"


int parse_cmd(char *argstr, char **test_args, int *args_run_idx)
{
	if (strlen(argstr) < 1) return -1;

	int head_idx;
	for (head_idx = 0; head_idx < strlen(argstr) && argstr[head_idx] == 32; head_idx++) {}
	char *arg = strtok(&argstr[head_idx], " ");
	int argc = 0;
	while (arg != NULL)
	{
		test_args[argc] = (char*) malloc((1 + strlen(arg)) * sizeof(char));
		if (strcmp(arg, "%") == 0)
			*args_run_idx = argc;
		memcpy(test_args[argc++], arg, 1 + strlen(arg));
		arg = strtok(NULL, " ");
	}
	return argc;
}



int main(int argc, char** argv)
{
	std::string test_command_std;
	read_test_options(&argc, &argv, &my_id, &test_command_std);

	int args_run_idx = -1;
	char *test_command_c = const_cast<char*>(test_command_std.c_str());
	char **test_args = (char**) malloc(MAX_ARG_NUM * MAX_ARG_LEN * sizeof(char));
	int cargc = parse_cmd(test_command_c, test_args, &args_run_idx);

	int pn_base_port = PN_DEFAULT_BASE_PORT;

	peer_net = new PeerNet(num_peers, my_id, rsa_prv_keyfile, pn_config_file, pn_base_port);

	if (peer_net->is_connected() & (cargc > 0))
	{
		timespec tv_delay;
		timespec *delay_ptr;
		if (test_delay_sec <= 0)
			delay_ptr = NULL;
		else
		{
			tv_delay.tv_sec = test_delay_sec / num_peers;
			tv_delay.tv_nsec = 0;
			delay_ptr = &tv_delay;
		}
		for (int peer_id = 0; peer_id < num_peers; peer_id++)
		{
			target_update_value |= (1 << peer_id);
			if (peer_id != my_id)
			{
				if (peer_net->peers()[peer_id].sock_fd + 1 > maxfdp1)
					maxfdp1 = peer_net->peers()[peer_id].sock_fd + 1;
			}
		}

		int test_error;
		int errors = 0;
		for (int run_number = 0; run_number < num_test_runs; run_number++)
		{
			if (args_run_idx >= 0)
				sprintf(test_args[args_run_idx], "%i", run_number);

			peer_net->multicast_ack(peer_net->PASS_RIGHT(), 1);

			pselect(maxfdp1, NULL, NULL, NULL, delay_ptr, NULL);

			test_error = run_test(run_number, test_args);

			if (!test_error || test_error == ACK)
			{
				//printf("\n\nController %i test run %i success\n\n", my_id, run_number);
			}
			else
			{
				printf("\n\nController %i test run %i fail\n\n", my_id, run_number);
				errors += 1;
			}
		}

		printf("Controller %i: %i errors detected out of %i runs\n", my_id, errors, num_test_runs);
	}

	for (int i = 0; i < cargc; i++)
	{
		free(test_args[i]);
	}

	delete peer_net;
	return EXIT_SUCCESS;
}




