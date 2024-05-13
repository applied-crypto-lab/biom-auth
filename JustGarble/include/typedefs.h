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


#ifndef _TYPE_DEFS_
#define _TYPE_DEFS_

#include "dkcipher.h"
#include <x86intrin.h>

typedef struct {
	long value, id;
	block label, label0, label1;
} Wire;

typedef struct {
	block label; long id;
} GarbledWire;


typedef struct {
	long type, id;
	Wire *input0, *input1, *output;
} Gate;

typedef struct {
	long input0, input1, output; int id, type;
} GarbledGate;


typedef char shortBlock[10];

#ifdef TRUNCATED
typedef struct {
	char table[4][10];

} GarbledTable;
#else
typedef struct {
	block table[4];
} GarbledTable;
#endif

typedef struct {
	int n,m,q,r;
	Gate* gates;
	Wire* wires;
	long id;
} Circuit;

typedef struct {
	int n, m, q, r;
	block* inputLabels, outputLabels;
	GarbledGate* garbledGates;
	GarbledTable* garbledTable;
	Wire* wires;
	int *outputs;
	long id;
	block globalKey;
} GarbledCircuit;

typedef struct {
	int m;
	block *outputLabels;
	long id;
} GarbledOutput;

typedef struct {
	long wireIndex, gateIndex, tableIndex;
	DKCipherContext dkCipherContext;
	int* fixedWires;
	int fixCount;
	block R;
} GarblingContext;


typedef block* InputLabels;
typedef block* ExtractedLabels;
typedef block* OutputMap;

/*
int createEmptyCircuit(Circuit *circuit, int n, int m, int q, int r);
int startBuilding(GarbledCircuit *gc, GarblingContext *ctx);
int finishBuilding(GarbledCircuit *garbledCircuit, GarblingContext *garbledContext, OutputMap outputMap, int *outputs);
int createEmptyGarbledCircuit(GarbledCircuit *garbledCircuit, int n, int m, int q, int r, InputLabels inputLabels);
int createInputLabels(InputLabels inputLabels, int n);
long garbleCircuit(GarbledCircuit *garbledCircuit, InputLabels inputLabels, OutputMap outputMap);
int evaluate(GarbledCircuit *garbledCircuit, ExtractedLabels extractedLabels, OutputMap outputMap);
int extractLabels(ExtractedLabels extractedLabels, InputLabels inputLabels, int* inputBits, int n);
int mapOutputs(OutputMap outputMap, OutputMap extractedMap, int *outputVals, int m);
int writeCircuitToFile(GarbledCircuit *garbledCircuit, char *fileName);
int readCircuitFromFile(GarbledCircuit *garbledCircuit, char *fileName);
*/

//#include "garble.h"
//#include "circuits.h"
//#include "check.h"
//#include "util.h"


#endif
