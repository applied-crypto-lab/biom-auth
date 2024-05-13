#!/bin/bash

###############################################################################
#	Privacy Preserving Biometric Authentication for Fingerprints and Beyond
#	Copyright (C) 2024  Marina Blanton and Dennis Murphy,
# University at Buffalo, State University of New York.
#
#	This program is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program.  If not, see <https://www.gnu.org/licenses/>.
###############################################################################


num_peers=3
num_tests=100
cfg_file=runtime-config-local
base_exe=mains/authentication_test
controller=mains/test_controller
PID=()

Config_Lines=()
while IFS= read -r line
do
  Config_Lines+=("$line")
done < "$cfg_file"

for threat_model in "sh" "mal"
do
  for dist_func in "cs" "ed"
  do
    echo
    echo "Running tests for threat model $threat_model and distance function $dist_func"
    echo
    base_exe_args="-df $dist_func -tm $threat_model -coff 1 -con 1"
    for ((peer_id = 0; peer_id < 3; peer_id++))
    do
      base_exe_key_file=prvkey$peer_id.pem
      controller_key_file=prvkey$peer_id.pem

      echo Executing command:
      echo "$controller -r $peer_id -np $num_peers -fc $cfg_file -fr $controller_key_file -nt $num_tests -c "${base_exe} -r ${peer_id} -fc ${cfg_file} -fr ${base_exe_key_file} -tr % ${base_exe_args}" &"

      $controller -r $peer_id -np $num_peers -fc $cfg_file -fr $controller_key_file -nt $num_tests -c "${base_exe} -r ${peer_id} -fc ${cfg_file} -fr ${base_exe_key_file} -tr % ${base_exe_args}" &

      PID[$peer_id]=$!
    done

    for ((peer_id = 0; peer_id < 3; peer_id++))
    do
      wait ${PID[$peer_id]}
    done

    echo
    sleep 1
  done
  echo
done

mv results/time_test_results_*.csv results/local/
mv results/comm_test_results_*.txt results/local/


