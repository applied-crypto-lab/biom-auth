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


#include "../include/garble.h"
#include "../include/common.h"
#include "../include/gates.h"
#include "../include/justGarble.h"

extern int ANDGate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int output);
extern int ORGate(GarbledCircuit *gc, GarblingContext *garblingContext, int input0, int input1, int output);
extern int XORGate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int output);
extern int NOTGate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext,  int input0, int output);

#ifdef ROW_REDUCTION

int genericGate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int output, int *vals, int type) {
	createNewWire(&(garbledCircuit->wires[output]), garblingContext, output);

	GarbledGate *garbledGate = &(garbledCircuit->garbledGates[garblingContext->gateIndex]);
	GarbledTable *garbledTable = &(garbledCircuit->garbledTable[garblingContext->tableIndex]);

	garbledGate->id = garblingContext->gateIndex;
	garbledGate->type = type;
	garbledGate->input0 = input0;
	garbledGate->input1 = input1;
	garbledGate->output = output;

	block blocks[4];
	block keys[4];
	long lsb0 = getLSB(garbledCircuit->wires[input0].label0);
	long lsb1 = getLSB(garbledCircuit->wires[input1].label0);
	block tweak;
	block keyToEncrypt;

	tweak = makeBlock(garblingContext->gateIndex, (long)0);
	garblingContext->gateIndex++;
	garblingContext->tableIndex++;

	return garbledGate->id;
}
#else

int genericGate(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext, int input0, int input1, int output, int *vals, int type) {
	createNewWire(&(garbledCircuit->wires[output]), garblingContext, output);
	GarbledGate *garbledGate = &(garbledCircuit->garbledGates[garblingContext->gateIndex]);

	garbledGate->id = garblingContext->gateIndex;
	garbledGate->type = type;
	garbledGate->input0 = input0;
	garbledGate->input1 = input1;
	garbledGate->output = output;

	garblingContext->gateIndex++;
	garblingContext->tableIndex++;
	return garbledGate->id;
}

#endif

int fixedZeroWire(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext) {
	int ind = getNextWire(garblingContext);
	garblingContext->fixedWires[ind] = FIXED_ZERO_WIRE;
	Wire *wire = &garbledCircuit->wires[ind];
	if (wire->id != 0)
		printf("ERROR: Reusing output at wire %d\n", ind);
	wire->id = ind;
	wire->label0 = randomBlock();
	wire->label1 = xorBlocks(garblingContext->R, wire->label0);
	return ind;

}
int fixedOneWire(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext) {
	int ind = getNextWire(garblingContext);
	garblingContext->fixedWires[ind] = FIXED_ONE_WIRE;
	Wire *wire = &garbledCircuit->wires[ind];
	wire->id = ind;
	wire->label0 = randomBlock();
	wire->label1 = xorBlocks(garblingContext->R, wire->label0);
	return ind;
}




