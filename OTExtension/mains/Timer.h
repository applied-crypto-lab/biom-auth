
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


#ifndef _PN_TIMER_
#define _PN_TIMER_

#include <cstdlib>
#include <cstring>
#include <cassert>
#include <iostream>
#include <fstream>
#include <cmath>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
//#include <fcntl.h>
#include <errno.h>
#include <time.h>



class Timer {

public:

	Timer();

	~Timer();

	//types

	struct timestruct
	{
		time_t sec;
		long subsec;
	};

	//functions

	void print_time(timestruct *tsct, int high_res_in);
	void timestamp();
	void timestamp(timespec *tsp, int* tidx);
	void process_timestamp(bool recording_time, int verbose, const char* msg);
	void process_results(std::string& id_str, std::string& test_params, int test_run_num);
	void copy(timestruct *dest, timestruct *source);
	double get_millies(timestruct *t1, timestruct *t2, int high_res_in);
	void get_sum(timestruct *t1, timestruct *t2, timestruct *t_out, int high_res_in, int high_res_out);
	void get_difference(timestruct *t1, timestruct *t2, timestruct *t_out, int high_res_in, int high_res_out);
	void get_const_product(timestruct *tsct, double factor, int high_res_in, int high_res_out);
	void update(timestruct *tsct, timestruct *tsc_elapsed, int high_res_timer);
	void update(timestruct *tsct, timestruct *tsc_elapsed, int high_res_timer, timespec *tsp, int* tidx);


	//variables



private:

	//types

	//functions

	void cleanup();

	//variables

	timespec tsp[2];
	int tidx = 0;

	int tcount = 0;
	std::vector<double> test_results;

};


#endif

