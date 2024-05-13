
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


#include "Timer.h"


Timer::Timer()

{
	timestamp();
	//print_time((timestruct*) &tsp[0], true);
	//print_time((timestruct*) &tsp[1], true);
}



Timer::~Timer()

{
	cleanup();
}



void Timer::cleanup()
{
	//
}



void Timer::print_time(timestruct *tsct, int high_res_in)
{
	printf("%li seconds, ", tsct->sec);
	if (high_res_in)
		printf("%li nanoseconds\n", tsct->subsec);
	else
		printf("%li microseconds\n", tsct->subsec);
}



void Timer::timestamp()
{
	clock_gettime(CLOCK_MONOTONIC_RAW, &tsp[tidx]);
	tidx = 1 - tidx;
}


void Timer::timestamp(timespec *tsp, int* tidx)
{
	clock_gettime(CLOCK_MONOTONIC_RAW, &tsp[*tidx]);
	*tidx = 1 - *tidx;
}


void Timer::process_timestamp(bool recording_time, int verbose, const char* msg)
{
	timestamp();
	double elapsed = get_millies(NULL, NULL, true);
	if (recording_time) test_results.push_back(elapsed);
	if (verbose) printf("Timestamp %i:\t\t%f\n", tcount++, elapsed);
	if (verbose && (msg != NULL)) printf("%s", msg);
}



void Timer::process_results(std::string& id_str, std::string& test_params, int test_run_num)
{
	double total_time = 0;
	for (int i = 0; i < test_results.size(); i++)
		total_time += (double) test_results[i];
	test_results.push_back(total_time);

	if (test_run_num >= 0)
	{
		std::ofstream results_file;
		if (test_run_num == 0)
			results_file.open("results/time_test_results_" + id_str + "_" + test_params + ".csv");
		else
			results_file.open("results/time_test_results_" + id_str + "_" + test_params + ".csv", std::ios::app);

		results_file << std::to_string(test_run_num) << ",," << std::to_string(test_results[0]);
		for (int i = 1; i < test_results.size(); i++)
		{
			results_file << "," << std::to_string(test_results[i]);
		}
		results_file << "\n";
		results_file.close();
	}
	else
		printf("Total duration:\t\t%f\n\n", total_time);
}


void Timer::copy(timestruct *dest, timestruct *source)
{
	dest->sec = source->sec;
	dest->subsec = source->subsec;
}


//CAUTION for all functions below this line,
//CAUTION t1 and t2 must be of the same type(resolution).
//CAUTION if they differ, promote timeval to timespec by multiplying tv_usec by 1000 prior to calling



double Timer::get_millies(timestruct *t1, timestruct *t2, int high_res_in)
{
	if ((t1 == NULL) || (t2 == NULL))
	{
		t1 = (timestruct*) &tsp[1-tidx];
		t2 = (timestruct*) &tsp[tidx];
		high_res_in = true;
	}
	timestruct tsc_elapsed;
	get_difference(t1, t2, &tsc_elapsed, high_res_in, true);
	double dbl_sec = (double) 1000 * tsc_elapsed.sec;
	double dbl_subsec;
	if (high_res_in)
		dbl_subsec = (double) tsc_elapsed.subsec / 1000000;
	else
		dbl_subsec = (double) tsc_elapsed.subsec / 1000;
	return dbl_sec + dbl_subsec;
}



void Timer::get_sum(timestruct *t1, timestruct *t2, timestruct *t_out, int high_res_in, int high_res_out)
{
	long sec = t1->sec + t2->sec;
	long subsec = t1->subsec + t2->subsec;
	long max_subsec = high_res_in ? 1000000000 : 1000000;
	if (t1->subsec + t2->subsec < max_subsec)
	{
		subsec = max_subsec - subsec;
		sec++;
	}
	t_out->sec = (time_t) sec;
	if (high_res_in & !high_res_out)
		t_out->subsec = subsec / 1000;
	else if (!high_res_in & high_res_out)
		t_out->subsec = subsec * 1000;
	else
		t_out->subsec = subsec;
}



//always returns positive magnitude of difference if result < 0
void Timer::get_difference(timestruct *t1, timestruct *t2, timestruct *t_out, int high_res_in, int high_res_out)
{
	long sec = t1->sec - t2->sec;
	long subsec = t1->subsec - t2->subsec;
	if (subsec < 0)
	{
		if (high_res_in)
			subsec += 1000000000;
		else
			subsec += 1000000;
		sec--;
	}
	if (sec < 0)
	{
		if (high_res_in)
			subsec = 1000000000 - subsec;
		else
			subsec = 1000000 - subsec;
		sec = ~sec;
	}
	t_out->sec = (time_t) sec;
	if (high_res_in & !high_res_out)
		t_out->subsec = subsec / 1000;
	else if (!high_res_in & high_res_out)
		t_out->subsec = subsec * 1000;
	else
		t_out->subsec = subsec;
}



//always returns positive magnitude of product if result < 0
void Timer::get_const_product(timestruct *tsct, double factor, int high_res_in, int high_res_out)
{
	double dbl_subsec;
	if (high_res_in)
		dbl_subsec = (double) (tsct->subsec) / 1000000000;
	else
		dbl_subsec = (double) (tsct->subsec) / 1000000;

	double dbl_time = (double) (tsct->sec + dbl_subsec);
	dbl_time *= factor;
	time_t sec = (time_t) round(dbl_time);
	dbl_time -= (double) sec;
	if (high_res_out)
		dbl_time *= 1000000000;
	else
		dbl_time *= 1000000;
	long subsec = (long) dbl_time;

	if (subsec < 0)
	{
		if (high_res_in)
			subsec += 1000000000;
		else
			subsec += 1000000;
		sec--;
	}
	if (sec < 0)
	{
		if (high_res_in)
			subsec = 1000000000 - subsec;
		else
			subsec = 1000000 - subsec;
		sec = ~sec;
	}

	tsct->sec = sec;
	tsct->subsec = subsec;
}



//takes timestamp and deducts differential from tsct
//facilitates countdown timers
void Timer::update(timestruct *tsct, timestruct *tsc_elapsed, int high_res_timer)
{
	bool allocating = tsc_elapsed == NULL;
	if (allocating)
		tsc_elapsed = (timestruct*) malloc(sizeof(timestruct));
	timestamp();
	get_difference((timestruct*) &tsp[1-tidx], (timestruct*) &tsp[tidx], tsc_elapsed, true, true);
	if (!high_res_timer)
		tsct->subsec *= 1000;
	if (tsct != NULL)
		get_difference(tsct, tsc_elapsed, tsct, true, high_res_timer);
	if (allocating)
		free(tsc_elapsed);
}


//takes timestamp and deducts differential from tsct
//facilitates countdown timers
void Timer::update(timestruct *tsct, timestruct *tsc_elapsed, int high_res_timer, timespec *tsp, int* tidx)
{
	bool allocating = tsc_elapsed == NULL;
	if (allocating)
		tsc_elapsed = (timestruct*) malloc(sizeof(timestruct));
	timestamp();
	get_difference((timestruct*) &tsp[1-*tidx], (timestruct*) &tsp[*tidx], tsc_elapsed, true, true);
	if (!high_res_timer)
		tsct->subsec *= 1000;
	if (tsct != NULL)
		get_difference(tsct, tsc_elapsed, tsct, true, high_res_timer);
	if (allocating)
		free(tsc_elapsed);
}



