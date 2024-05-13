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

peer_id=$1
net_setting=$2
net_device=$3
cfg_file_sufx=$4
num_peers=3
num_tests=100
controller=mains/test_controller
base_exe=mains/authentication_test
Net_Settings=("local" "LAN" "internet")

if [[ "$cfg_file_sufx" == "" ]]; then
  cfg_file_sufx=local
fi

cfg_file=runtime-config-$cfg_file_sufx

notify_and_quit()
{
	echo
	echo $1
	echo
	echo "Usage: ./batch_test.sh <peer_id> <config file suffix> <network setting> <network device name>"
	echo
	echo "peerid in [0..2], netowrk_setting in [local, LAN, internet]"
	echo
	exit
}

if ! [[ ${Net_Settings[@]} =~ $net_setting ]]; then
  notify_and_quit "Invalid network setting: $net_setting"
fi

if { ! [[ $peer_id =~ [0-9]+ ]]; }  || (( $peer_id < 0 )) || (( $peer_id >= $num_peers )); then
  notify_and_quit "peer id $peer_id out of range"
fi

for threat_model in "sh" "mal"
do
  for dist_func in "cs" "ed"
  do
    echo
    echo "Running tests for network model $net_setting, threat model $threat_model, and distance function $dist_func"
    echo
    base_exe_args="-df $dist_func -tm $threat_model -coff 1 -con 1"
    base_exe_key_file=prvkey$peer_id.pem
    controller_key_file=prvkey$peer_id.pem

    echo Executing command:
    echo "$controller -r $peer_id -np $num_peers -fc $cfg_file -fr $controller_key_file -nt $num_tests -c "${base_exe} -r ${peer_id} -fc ${cfg_file} -fr ${base_exe_key_file} -tr % ${base_exe_args}""

    $controller -r $peer_id -np $num_peers -fc $cfg_file -fr $controller_key_file -nt $num_tests -c "${base_exe} -r ${peer_id} -fc ${cfg_file} -fr ${base_exe_key_file} -tr % ${base_exe_args}"

    echo
    sleep 1
  done
  echo
done

mv results/time_test_results_*.csv results/$net_setting/
mv results/comm_test_results_*.txt results/$net_setting/




