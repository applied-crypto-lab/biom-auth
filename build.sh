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


notify_and_quit()
{
	echo
	echo $1
	echo
	exit
}

cd OTExtension/build
cmake .. && make || notify_and_quit "Project build failed"

eval ./rsakeygen.sh 3

cd ../../JustGarble/
echo

for threat_model in "sh" "mal"
do
  for dist_func in "cs" "ed"
  do
    echo "Generating biometric authentication circuit for $threat_model security, $dist_func distance function"
    eval bin/circuit_test_and_gen $dist_func 192 8 $threat_model > ../OTExtension/build/results/$dist_func-192-8-$threat_model.txt
  done
done

echo
cp -a circuit_files/* ../OTExtension/build/circuit_files/
echo "Circuit files copied to OTExtension/build/circuit_files and JustGarble/circuit_files"
echo
echo "Circuit information saved in OTExtension/build/results"
echo
