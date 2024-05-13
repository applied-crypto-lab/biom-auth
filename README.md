# biom-auth

This repository corresponds to the implementation in the article "**Privacy Preserving Biometric Authentication for Fingerprints and Beyond**" by Marina Blanton and Dennis Murphy published in the Proceedings of the Fourteenth ACM Conference on Data and Application Security and Privacy (CODASPY), 2024. The full version can be found [here](https://eprint.iacr.org/2024/525.pdf).

Our code modifies, extends, and integrates the following two code bases:

  - OTExtension
    - The publication most relevant to our work is that of More Efficient Oblivious Transfer Extensions with Security for Malicious Adversaries (Asharov, Lindell, Schneider, and Zohner), and can be found [here](https://eprint.iacr.org/2015/061.pdf).
    - Further information about this and other related works, and the originating code library can be found at the repository: [encryptogroup/OTExtension repository](https://github.com/encryptogroup/OTExtension).
  - JustGarble
    - The relevant work is Constructing Cryptographic Hash Functions from Fixed-Key Blockciphers (Bellare, Hoang, Keelveedhi, and Rogaway), and can be found [here](https://www.iacr.org/cryptodb/data/paper.php?pubkey=23874).
    - The original source code can be obtained here: [JustGarble Code](https://cseweb.ucsd.edu/groups/justgarble/).

Note that you do not need to independently obtain this code in order to clone, build, and use our codebase, but we provide the links here for reference.


## Description
Our work treats outsourced biometric authentication in a two-phase, one-client two-server model, where one server is considered to be the primary server (and is always considered non-malicious). Specifically, we treat two adversarial models: one in which both servers are semihonest and only the client is malicious, and the other where the second "helper" server is malicious and possibly colludes with the client. We focus our experiments on using cosine similarity and Euclidean distance with respect to the fixed length fingerprint representation due to Engelsma, Cao, and Jain, found in this [paper](https://arxiv.org/pdf/1909.09901). Our codebase tests our protocol in two network settings, LAN, and mixed internet. Details can be found in the paper above and the experiments are intended to replicate the scenarios found in Table 1 therein.

Additional relevant functionality is included within our codebase and may be helpful in its own right, such as computation of boolean gates via oblivious transfer, as well as garbled circuits evaluating Hamming distance comparison, floating point operations, SHA- and AES-circuits. We also extend JustGarble to include systematic efficient incorporation of constant public input values.

## Usage

### Set up the environment
The following assumes a Linux machine with a BASH shell, and if applicable (for results collecting in reproducibility experiments) an up to date Python interpreter installed (version 3.6+). This code has been verified to work on current Ubuntu and openSUSE installations.

Our source code is hosted in a GitHub repository, with instructions described below. The following software is required (all available free of charge):

  - GNU gcc g++ compiler version 8.0+
  - GMP (The GNU Multiple Precision Arithmetic Library), including development tools
  - openSSL library, including development tools
  - Boost library (all), version 1.66+, including development tools
  - msgpack
  - CMake, version 3.12+
  - make

You can download the repository using HTTPS, SSH, or GitHub CLI. The respective commands (any one of which will suffice) are:

```bash
git clone https://github.com/applied-crypto-lab/biom-auth.git
git clone git@github.com:applied-crypto-lab/biom-auth.git
gh repo clone applied-crypto-lab/biom-auth
```

Once the libraries are installed and the repository is downloaded, navigate to the ```biom-auth``` directory of the local repository and run

```bash
./build.sh
```


## Running the Experiments

We provide two bash shell scripts, `batch_test.sh` and `batch_test_local.sh`. These are located in `biom-auth/OTExtension/build/`.

### To run the relevant tests, do the following:

Open three terminals in the `biom-auth/OTExtension/build/` directory. Then in each, run the following command with the same arguments, with the exception that each peer id in {0, 1, 2} is invoked exactly once. The instances do not need to be started in any particular order.

  - `batch_test.sh` runs all relevant test for a given network setting, based on a configuration you provide.
    - It is expected that a file named `runtime-conif-<config file suffix>` exists in the host working directory (`runtime-config-local` is provided; details are given below).
    - The command structure is
      - `./batch_test.sh <peer_id> <network setting> <network device name> <config file suffix>`
        - `<peer id>` in {0, 1, 2} == {Server 1, Server 2, Client}.
        - `<config file suffix>`
          - The name of the config file must be of the form "runtime-config-X" where X can be any name you would like to give any custom file you create.
          - We have provided a file named runtime-config-local, which is the default file if this parameter is left blank. This file is set up to allow testing of all computational parties on the same machine.
          - In order to use this program in a true distributed network environment, one would need to enter the IP addresses, ports, and key files where your machines can accept TCP communication, into a copy of this file and rename it with a different suffix.
        - `<network setting>` in {"local", "LAN", "internet"}.
        - `<network device name>` is the name of the network interface you wish to use. `eth0` is default, but you should check this on each machine. If the `iproute` package is installed, you can issue `ip -o link show` to obtain a list of active network devices.
    - The results will be stored in csv files and moved to the subdirectory of `biom-auth/OTExtension/build/results` corresponding to `<network setting>`.
  - `batch_test_local.sh` runs all relevant test on the localhost. This is a bit faster than the LAN scenario and not directly tested in our results, but can be used immediately after installation and building to verify that the core functionality works properly.
    - Results will be saved to `biom-auth/OTExtension/build/results/local`.
    - This shell script takes no parameters. In particular, `runtime-config-local` is used for this since no other configuration is meaningful.


### Collecting experimental data:

  - Each test parameterization will output individual `time_test_results_*.csv` and `comm_test_results_*.csv` files, for timing and communication respectively.
  - After all tests have completed, from within the `biom-auth/OTExtension/build` directory, issue `python3 extract_time_results.py results`.
    - The time results will be collected and averaged from the raw files output by the test programs, and the results will be placed in `biom-auth/OTExtension/build/results/compiled_test_results.csv`.
  - Note that during the build process, fresh authentication circuits are generated for use in testing and stored in `biom-auth/OTExtension/build/circuit_files` as well as `biom-auth/JustGarble/circuit_files`.
    - Circuit information is output into files `cs-192-8-sh.txt`, `cs-192-8-mal.txt`, `ed-192-8-sh.txt`, and `ed-192-8-mal.txt`.
    - This information includes the number of gates and wires, along with breakdown of gates by type.
    - A number of simulations are also run concurrently with circuit generation, and results from these are provided, including total number of clock cycles and cycles per gate, for each of garbling and evaluation time.

### Generating new circuits for use in JustGarble

As part of the build process, the program to generate and test boolean circuits for use in JustGarble is compiled and used to generate new circuits. The program can be used in conjunction with the codebase to generate modified authentication circuits, and can be adapted for more general purposes. It can be found in `biom-auth/JustGarble/bin` and is used as follows:

  - The command structure is
    - `./circuit_test_and_gen.sh <algorithm> <num inputs> <input length> <opts...>`
      - `<algorithm>` in
        - `cust` - Custom Alg
        - `hd` - Hamming Distance
        - `cs` - Cosine Similarity
        - `ed` - Euclidean Distance
        - `file` - Alg loaded from file
        - `all` - All Algs
      - `<num inputs>` is the length of the biometric input vector.
      - `<input length>` is the size of each biometric input vector element.
      - `<num inputs>` and `<input length>` apply to `<algorithm> != file`, and must be unsigned integers signifying a number of inputs, and respectively, the length of each, which are appropriate for the chosen algorithm.
      - If `<algorithm> == file`, then either
        - the next argument is a filename, which should be found in `biom-auth/JustGarble/circuit_files`, or
        - no argument follows, and a menu listing the files in `biom-auth/JustGarble/circuit_files` will be provided, with the option to select one for simulation.
      - if `<algorithm> != file`, then `<opts...>` may be:
        - General options:
          - `new` - if you wish to force a new circuit build rather than automatically read from file.
        - Biometric authentication specific options:
          - `mal` - if you wish to include commitment checking and output the result as a second bit.
          - `sha3-256` - if you wish to use SHA3-256 as the commitment function (default is SHA2-256)
    - Note that you may issue 'make cleanscd' to delete all saved circuit files.




