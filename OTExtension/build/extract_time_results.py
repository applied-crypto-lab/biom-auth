
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


import sys, os

#NOTE preexisting compiled file will be deleted. Please rename\relocate any important previous result files

S1 = 0
S2 = 1
C = 2


def average(S):
  return sum(S) / len(S)


def matrix_col(M, col_idx):
  N = []
  for row in range(len(M)):
    if len(M[row]) > col_idx:
      N.append(float(M[row][col_idx]))
    else:
      N.append(None)
  return N


def process_data(test_data, net_model, threat_model, dist_func, results_dir):

  GARB_IDX = 3
  SEND_IDX = 5
  EVAL_IDX = 9
  OT_IDX = 9
  ONL_TOT_IDX = 8
  OFFL_TOT_UP_IDX = 5
  if threat_model == "mal":
    EVAL_IDX += 2
    OFFL_TOT_UP_IDX += 2

  garb_time = average(matrix_col(test_data[S1], GARB_IDX))
  gt_send_time = average(matrix_col(test_data[S1], SEND_IDX))
  offline_tot_time = sum([average(matrix_col(test_data[S1], col_idx)) for col_idx in range(2, 1 + OFFL_TOT_UP_IDX)])
  eval_time = average(matrix_col(test_data[S2], EVAL_IDX))
  ot_time = min(average(matrix_col(test_data[S1], OT_IDX)), average(matrix_col(test_data[S2], OT_IDX)))
  online_tot_time = average(matrix_col(test_data[C], ONL_TOT_IDX))
  online_other_time = online_tot_time - eval_time - ot_time

  '''
  out_text_file_name = results_dir + "compiled_time_test_results" + "_" + threat_model + "_" + dist_func + ".txt"
  out_text_file = open(out_text_file_name, 'w')
  out_text_file.write("\nGarbling:\t" + str(garb_time) + "\n")
  out_text_file.write("Sending gtable:\t" + str(gt_send_time) + "\n")
  out_text_file.write("Total offline\t" +  str(offline_tot_time) + "\n")
  out_text_file.write("Eval:\t" + str(eval_time) + "\n")
  out_text_file.write("OT:\t" + str(ot_time) + "\n")
  out_text_file.write("Other online:\t" + str(online_other_time) + "\n")
  out_text_file.write("Total online\t" + str(online_tot_time) + "\n")
  out_text_file.close()
  '''

  out_csv_file = open(out_csv_file_name, 'a')
  out_csv_file.write(net_model + "," + threat_model + "," + dist_func + ",,")
  out_csv_file.write(str(eval_time) + "," + str(ot_time) + "," + str(online_other_time) + "," + str(online_tot_time) + ",,")
  out_csv_file.write(str(garb_time) + "," + str(gt_send_time) + "," + str(offline_tot_time) + "\n")
  out_csv_file.close()



try:
  results_dir = sys.argv[1]
  if not os.path.isdir(sys.argv[1]):
    raise Exception
except:
  print("Argument 1 should be a directory")
  exit()

if results_dir[-1] != '/':
	results_dir += '/'

parties = ["S1", "S2", "C"]

out_csv_file_name = results_dir + "compiled_time_test_results.csv"
out_csv_file = open(out_csv_file_name, 'w')
out_csv_file.write(",,,,Online time,,,,,Offline time,,\n")
out_csv_file.write("Network model,Threat model, Distance function,,GCE,OT,Other,Total,,Garble,Send,Total\n")
out_csv_file.write("\n")
out_csv_file.close()

for net_model in ["local", "LAN", "internet"]:
  for threat_model in ["sh", "mal"]:
    for dist_func in ["cs", "ed"]:
      csv_names = []
      csv_splits = []
      all_files_found = True
      for party in parties:
        results_fname = results_dir + net_model + "/time_test_results_" + party + "_" + threat_model + "_" + dist_func + ".csv"
        if not os.path.isfile(results_fname):
          #print("Cannot find results file", results_fname)
          all_files_found = False
          continue
        csv_names.append(results_fname)
        csv_file = open(results_fname, "r")
        csv_lines = csv_file.readlines()
        csv_file.close()
        csv_splits.append([line.split(",") for line in csv_lines if ((',,,' not in line) and (len(line) > 2))])
      if all_files_found:
        process_data(csv_splits, net_model, threat_model, dist_func, results_dir)
        print("Processed time results for net model", net_model, "threat model", threat_model, "and distance function", dist_func)
  out_csv_file = open(out_csv_file_name, 'a')
  out_csv_file.write("\n")
  out_csv_file.close()

print("Timing data compiled")



