
/*
 This file is part of JustGarble.

    JustGarble is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    JustGarble is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with JustGarble.  If not, see <http://www.gnu.org/licenses/>.

*/

/* NOTE This file has been modified from its original form for use in the applied-crypto-lab/biom-auth codebase */


#ifndef _AES_CIRCUITS_
#define _AES_CIRCUITS_

//#include "../include/garble.h"
//#include "../include/common.h"
#include "../include/gates.h"
//#include "../include/justGarble.h"

/*******
 * These AES circuits were modeled after the AES circuits of
 * the MPC system due to
 * Huang, Evans, Katz and Malka, available at mightbeevil.org
 */



inline int SquareCircuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int n, int* inputs, int* outputs)
{
	outputs[0] = getNextWire(garblingContext);
	XORGate(garbledCircuit, garblingContext, inputs[0], inputs[2], outputs[0]);

	outputs[1] = inputs[2];
	outputs[2] = getNextWire(garblingContext);
	XORGate(garbledCircuit, garblingContext, inputs[1], inputs[3], outputs[2]);

	outputs[3] = inputs[3];
	return 0;

}


#endif
