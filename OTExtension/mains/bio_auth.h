
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


#ifndef _PROT_2_
#define _PROT_2_


#include "PeerNet.h"

#define S1_ID 0
#define S2_ID 1
#define C_ID 2

#define DEFAULT_BIOMETRIC_INPUT_LENGTH 32
#define COMPRESSED_BIOMETRIC_INPUT_LENGTH 8

#define SEMIHONEST 0
#define MALICIOUS 1

#define group_ACK()\
errors_detected = peer_net->multicast_ack(peer_net->ALL_SEND_AND_RECEIVE(), 1);\
\
if (errors_detected)\
{\
	printf("Group ACK Error\n");\
}\
else if (verbose)\
{\
	printf("Group ACK Succeess\n");\
}

#endif

