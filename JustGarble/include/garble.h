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


#ifndef garble
#define garble 0

#include "common.h"
#include "justGarble.h"
//#include "dkcipher.h"



#define FIXED_ZERO_WIRE 0
#define FIXED_ONE_WIRE 15
#define INPUT_VAL_WIRE 16
#define OUTPUT_VAL_WIRE 31
#define VARIABLE_VAL_WIRE 32
#define ANDGATE 8
#define ORGATE 14
#define XORGATE 6
#define NOTGATE 5

#define TABLE_ID -1
#define XOR_ID -2
#define NOT_ID -3

int createNewGate(Gate *gate, Wire *input0, Wire *input1, Wire *output, int type );
int createNewWire(Wire *in, GarblingContext *garblingContext, int id);
int getNextWire(GarblingContext *garblingContext);
void removeGarbledCircuit(GarbledCircuit *garbledCircuit);
int blockEqual(block a, block b);

extern unsigned long startTime, endTime;

#endif
