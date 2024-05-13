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


#ifndef GATES_H_
#define GATES_H_

//#include "../include/garble.h"
//#include "../include/common.h"
#include "../include/justGarble.h"


int fixedZeroWire(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext);
int fixedOneWire(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext);
int genericGate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int output, int *vals, int type);

inline int ANDGate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int output) {
	int vals[] = { 0, 0, 0, 1 };
	return genericGate(garbledCircuit, garblingContext, input0, input1, output, vals, ANDGATE);
}

#ifdef FREE_XOR

inline int XORGate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int output) {
	if(garbledCircuit->wires[input0].id == 0) {
		printf("ERROR: Uninitialized input at wire 0 %d, gate %ld\n", input0, garblingContext->gateIndex);
	}
	if(garbledCircuit->wires[input1].id == 0) {
		printf("ERROR: Uninitialized input at wire 1 %d, gate %ld\n", input1, garblingContext->gateIndex);
	}
	if(garbledCircuit->wires[output].id != 0) {
		printf("ERROR: Reusing output at wire %d\n", output);
	}
	createNewWire(&(garbledCircuit->wires[output]), garblingContext, output);

	garbledCircuit->wires[output].label0 = xorBlocks(garbledCircuit->wires[input0].label0, garbledCircuit->wires[input1].label0);
	garbledCircuit->wires[output].label1 = xorBlocks(garbledCircuit->wires[input0].label1, garbledCircuit->wires[input1].label0);
	GarbledGate *garbledGate = &(garbledCircuit->garbledGates[garblingContext->gateIndex]);
	if (garbledGate->id != 0)
	dbgs("Reusing a gate");
	garbledGate->id = XOR_ID;
	garbledGate->type = XORGATE;
	garblingContext->gateIndex++;
	garbledGate->input0 = input0;
	garbledGate->input1 = input1;
	garbledGate->output = output;

	return 0;

}

#else
inline int XORGate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int output) {
	int vals[] = { 0, 1, 1, 0 };
	return genericGate(garbledCircuit, garblingContext, input0, input1, output, vals, XORGATE);
}
#endif

inline int ORGate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int output) {
	int vals[] = { 0, 1, 1, 1 };
	return genericGate(garbledCircuit, garblingContext, input0, input1, output, vals, ORGATE);
}

inline int NOTGate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int output) {
	int vals[] = { 1, 0, 1, 0 };
	return genericGate(garbledCircuit, garblingContext, 0, input0, output, vals,
			NOTGATE);
}




#endif /* GATES_H_ */
