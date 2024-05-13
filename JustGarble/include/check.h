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


#include "garble.h"

#ifndef CHECK_H_
#define CHECK_H_
int checkCircuit(GarbledCircuit *garbledCircuit, InputLabels inputLabels,
				 OutputMap outputMap, int num_inputs, int input_length, int check(int *inputs, int *outputs, int num_inputs, int input_length));
unsigned long timedEval(GarbledCircuit *garbledCircuit, InputLabels inputLabels);


#endif /* CHECK_H_ */


