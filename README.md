# Oblivious Message Retrieval: proof of concept C++ implementation for OMR

## Authors and paper

The (G)OMR library is developed by [Zeyu (Thomas) Liu](https://zeyuthomasliu.github.io/), [Eran Tromer](https://www.tau.ac.il/~tromer/) and [Yunhao Wang](https://wyunhao.github.io/) based on paper [Oblivious Message Retrieval](https://eprint.iacr.org/2021/1256.pdf) and paper [Group Oblivious Message Retrieval](https://eprint.iacr.org/2023/534.pdf).

### Abstract:
Anonymous message delivery systems, such as private messaging services and privacypreserving payment systems, need a mechanism for recipients to retrieve the messages
addressed to them, without leaking metadata or letting their messages be linked. Recipients could download all posted messages and scan for those addressed to them, but
communication and computation costs are excessive at scale.
We show how untrusted servers can detect messages on behalf of recipients, and summarize these into a compact encrypted digest that recipients can easily decrypt. These servers
operate obliviously and do not learn anything about which messages are addressed to which
recipients. Privacy, soundness, and completeness hold even if everyone but the recipient is
adversarial and colluding (unlike in prior schemes), and are post-quantum secure.
Our starting point is an asymptotically-efficient approach, using Fully Homomorphic
Encryption and homomorphically-encoded Sparse Random Linear Codes. We then address
the concrete performance using a bespoke tailoring of lattice-based cryptographic components, alongside various algebraic and algorithmic optimizations. This reduces the digest
size to a few bits per message scanned. Concretely, the servers’ cost is a couple of USD per
million messages scanned, and the resulting digests can be decoded by recipients in under
20ms. Our schemes can thus practically attain the strongest form of receiver privacy for
current applications such as privacy-preserving cryptocurrencies.

We further consider the case of group messaging, where each message may have multiple recipients 
(e.g., in a group chat or blockchain transaction).
A direct use of prior OMR protocols in the group setting increases the servers’ work linearly in the group size, rendering it prohibitively costly for large groups.
We thus devise new protocols where the servers’ cost grows very slowly with the group size, while
recipients’ cost is low and independent of the group size. Our approach builds on and improves on prior work. The efficient handling
of groups is attained by encoding multiple recipient-specific clues into a single polynomial or multilinear
function that can be efficiently evaluated under FHE, and via preprocessing and amortization techniques.
We formally study several variants of Group Oblivious Message Retrieval (GOMR), and describe
corresponding GOMR protocols. Our implementation and benchmarks show, for parameters of interest,
cost reductions of orders of magnitude compared to prior schemes. For example, the servers’ cost is
∼$3.36 per million messages scanned, where each message may address up to 15 recipients.

## License
The OMR library is developed by [Zeyu (Thomas) Liu](https://zeyuthomasliu.github.io/), [Eran Tromer](https://www.tau.ac.il/~tromer/) and [Yunhao Wang](https://wyunhao.github.io/), and is released under the MIT License (see the LICENSE file).

## Overview
The following diagram demonstrates the main components of OMR:

![omr](omrHighLevel.png)

We study two models with respect to GOMR,
which differ in how groups are formed, motivated by different applications:

The first flavor is the Ad-hoc GOMR (AGOMR), which allows the senders to send messages to a group of recipients chosen arbitrarily.
This suits cases such as messaging protocols (e.g., WhatsApp Broadcast Lists)
that let a message be addressed to any set of recipients chosen on the fly, or blockchains where transactions may have many recipients chosen arbitrarily.

The second flavor is Fixed GOMR (FGOMR), where groups are pre-formed by their members and then addressed collectively.
This suits applications with a notion of persistent groups, such as mailing lists or
group chats.
It also suits blockchains applications in which transactions need to be visible to a set of parties in addition to the recipient (e.g., auditors or jurisdictional law enforcement).
The FGOMR setting is a special case of AGOMR, where having pre-formed groups FGOMR allows for more efficient constructions,
and a stronger Denial-of-Service property (two honest recipients cannot be spammed jointly if they did not agree to join the same group).

The following diagrams demonstrate the main components of, AGOMR and FGOMR. Please refer to our paper for more details.

![agomr](agomrHighLevel.png)
![fgomr](fgomrHighLevel.png)

### Model Overview (Section 4.1 in [OMR](https://eprint.iacr.org/2021/1256.pdf), and Section 2.1 in [GOMR](https://eprint.iacr.org/2023/534.pdf))
In our system, we have a bulletin board (or board), denoted *BB*, that is publicly available contatining *N* messages. Each message is sent from some sender and is addressed to some recipient(s), whose identities are supposed to remain private.

A message consists of a pair (*xi*, *ci*) where *xi* is the message payload to convey, and *ci* is a clue string which helps notify the intended recipient (and only them) that the message is addressed to them.

In OMR, to generate the clue, the sender grabs the target recipient's *clue key*. In GOMR, the sender uses all the individual *clue keys* of the intended recipients, or alternatively, a *group clue key* jointly generated by the intended group of recipients. *Clue keys*, or *group clue keys*, are assumed to be published or otherwise communicated by some authenticated channels (whose details are
outside our scope).

At any time, any potential recipient *p* may want to retrieve the messages in *BB* that are addressed to them. We call these messages pertinent (to *p*), and the rest are impertinent.

A server, called a detector, helps the recipient *p* detect which message indices in *BB* are pertinent to them, or retrieve the payloads of the pertinent messages. This is done obliviously: even a malicious detector learns nothing about which messages are pertinent. The recipient gives the detector their detection key and a bound *ḱ* on the number of pertinent messages they expect to receive. The detector then accumulates all of the pertinent messages in *BB* into string *M*, called the digest, and sends it to the recipient *p*.

The recipient *p* processes *M* to recover all of the pertinent messages with high probability, assuming a semi-honest detector and that the number of pertinent messages did not exceed *ḱ*.

## What's in the demo

### Oblivious Message Detection
- Obliviously identify the pertinent messages and pack all their indices into a into a single digest.
- Schemes benchmarked: OMD1p (section 7.2)
- Measured
    - Key size: ~99MB
    - Detector running time, with Intel-HEXL: ~0.021 sec/msg
    - Detector running time, w/o  Intel-HEXL: ~0.030 sec/msg
    - Recipient running time: ~0.005 sec
    - Digest size: ~280KB

### Oblivious Message Retrieval
- Obliviously identify the pertinent messages and pack all their contents into a into a single digest.
- Schemes benchmarked: OMR1p (Section 7.4) and OMR2p (Section 7.5) in [OMR](https://eprint.iacr.org/2021/1256.pdf)
- Measured: 
    - Key sizes: ~129MB
    - detector running time (1-core, with Intel-HEXL): ~0.145 sec/msg and ~0.155 sec/msg
    - detector running time (2-core, with Intel-HEXL): ~0.075 sec/msg and ~0.085 sec/msg
    - detector running time (4-core, with Intel-HEXL): ~0.065 sec/msg and ~0.072 sec/msg
    - detector running time (1-core, w/o  Intel-HEXL): ~0.215 sec/msg and ~0.246 sec/msg
    - detector running time (2-core, w/o  Intel-HEXL): ~0.108 sec/msg and ~0.123 sec/msg
    - detector running time (4-core, w/o  Intel-HEXL): ~0.099 sec/msg and ~0.115 sec/msg
    - recipient running time: ~0.02 sec and ~0.063 sec
    - Digest size: ~560KB

### Group Oblivious Message Retrieval
- Obliviously identify the pertinent messages that are addressed to a group of recipients and pack all their contents into a into a single digest, which will be sent to one of the recipients inside the intended groups.
- Schemes benchmarked (in [GOMR](https://eprint.iacr.org/2023/534.pdf)): 
    - main schemes AGOMR3 (Section 6.2) (which is GOMR2_ObliviousMultiplexer_BFV in the code) and FGOMR1 (Section 7.4) (which is GOMR2_FG in the code)
    - their corresponding weak version AGOMR2 (Remark 6.2) (which is GOMR2_ObliviousMultiplexer_BFV in the weak branch) and FGOMR2 (Remark 7.4) (which is GOMR2_FG in the weak branch)
- Measured: 
    - Clue sizes (with group size = 15):
        - AGOMR: ~15300 Byte/msg
        - FGOMR: ~1100 Byte/msg
    - Clue key sizes (with group size = 15):
        - AGOMR: 133K per recipient
        - FGOMR: 1.56M per group
    - Detection key size (with group size = 15): ~140M
    - Digest size: ~35 Byte/msg
    - Recipient run time: ~0.02 sec
    - Detector run time:
![gomr_detector](detectortimescale.png)


### Parameters 
- OMR: N = 2^19 (or *N* = 500,000 padded to 2^19), k = *ḱ* = 50. Benchmark results on a Google ComputeCloudc2-standard-4instance type (4 hyperthreads of an Intel Xeon 3.10 GHz CPU with 16GB RAM) are reported in Section 10 in [OMR paper](https://eprint.iacr.org/2021/1256.pdf).
- FGOMR:  N = 2^15 (or *N* = 32,768), P = 2^60, G' = G+4, k = *ḱ* = 50, other detailed parameters please refer to our paper. Benchmark results for AGOMR with grou size ≥45, we use e8-highmem-64 instance, 64GB RAM (with a 128GB balanced disk), otherwise, we use e2-standard-2 instance type with 8GB RAM. Note that the runtime of the instance e8-highmem-64 is roughly the same as e2-standard-2. Detailed performance report can be found in Section 9 in [GOMR paper](https://eprint.iacr.org/2023/534.pdf).

## Dependencies

The OMR library relies on the following:

- C++ build environment
- CMake build infrastructure
- [SEAL](https://github.com/microsoft/SEAL) library 3.6 or 3.7 and all its dependencies
- [PALISADE](https://gitlab.com/palisade/palisade-release) library release v1.11.2 and all its dependencies (as v1.11.2 is not publicly available anymore when this repository is made public, we use v1.11.3 in the instructions instead)
- [NTL](https://libntl.org/) library 11.4.3 and all its dependencies
- [OpenSSL](https://github.com/openssl/openssl) library on branch OpenSSL_1_1_1-stable
- (Optional) [HEXL](https://github.com/intel/hexl) library 1.2.3

### Scripts to install the dependencies and build the binary
```
LIBDIR=~/ObliviousMessageRetrieval   # change to you want the dependency libraries installed

sudo apt-get install autoconf # if no autoconf
sudo apt-get install cmake # if no cmake
sudo apt-get install libgmp3-dev # if no gmp
sudo apt-get install libntl-dev=11.4.3-1build1 # if no ntl

git clone -b v1.11.3 https://gitlab.com/palisade/palisade-release
cd palisade-release
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=$LIBDIR
make -j
make install

git clone -b OpenSSL_1_1_1-stable https://github.com/openssl/openssl
cd openssl
./configure
make
sudo make install

# Optional
git clone --branch 1.2.3 https://github.com/intel/hexl
cd hexl
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$LIBDIR
cmake --build build
cmake --install build

git clone https://github.com/microsoft/SEAL
cd SEAL
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$LIBDIR \
-DSEAL_USE_INTEL_HEXL=ON 

cmake --build build
cmake --install build

git clone https://github.com/ZeyuThomasLiu/ObliviousMessageRetrieval 
cd ObliviousMessageRetrieval 
mkdir build
cd build
mkdir ../data
mkdir ../data/payloads
mkdir ../data/clues
mkdir ../data/cluePoly
mkdir ../data/processedCM
cmake .. -DCMAKE_PREFIX_PATH=$LIBDIR
make
```

### To Run

```
cd ~/ObliviousMessageRetrieval/build
./OMRdemos
```

## Summary of Constructions
This is a high-level summary of our [paper](https://eprint.iacr.org/2021/1256.pdf).

### Generic Fully Homomorphic Encryption (FHE) (Section 5.3)
Generic-FHE has a special functionality we call "recrypt" (which is essentially the "bootstrapping" operation used in other literatures) that homomorphically decrypts an FHE ciphertext into another FHE ciphertext encrypted under the secret key corresponding to the recryption key (or bootstrapping key, and is public). 
We assume that suppose the plaintext space is *Z_p*, if an FHE ciphertext is encrypting 1 under sk1, and we recrypt that ciphertext using pk2 corresponding another secret key sk2, then the probability that the recrypted ciphertext encrypts 1 under sk2 has probability <= 1/*p* + negl. This is satisfied by FHE schemes like [FHEW](https://eprint.iacr.org/2014/816) or [TFHE](https://eprint.iacr.org/2018/421).

### Naive Process (Section 6.1.1)
Each sender encrypts ℓ FHE ciphertexts each encrypting 1 using the public key of the recipient, and therefore the recrypted ciphertexts will still be 1 with probability 1-negl for pertinent messages, and will only have probability 1/*p* to be 1 for impertinent messages. 
We then compute the AND gate over all ℓ recrypted ciphertexts resulting into 1 ciphertext, which is 1 for pertinent messages, and 0 with probability (1-(1/*p*)^ℓ) for impertinent messages. We call the resulted ciphertexts a vector of pertinency indicators (PV).

### Randomized PV compression (Section 6.1.2)
Assuming there are at most *ḱ* pertinent messages, we first prepare m buckets (each of which is just a vector FHE ciphertext ciphertexts used to represent numbers in *Z_N*), where *m* >> *ḱ*. Then, we randomly distribute (PV_*i*×*i*), *i* \in \[*N*\] into those m buckets. If there is no collision, the recipient can just decrypt the buckets and obtain all the pertinent indices. To detect the collision, we keep a counter for each bucket. 

### Reducing Failure Rate (Section 6.1.2)
If there is a collision, the process fails. Let's say the collision rate is *p*. We can repeat the above process *C* trails, and this gives us a failure probability of *p^C*. To further reduce the failure rate, we can gather partial information from each trail and gather the information together.

### Payload Retrieval (Section 6.2)
So far we have only collected indices. To collect all the payloads, we can just compute (PV_*i*×payload_*i*) and send all i \in \[N\]. To make it compact, we use Ramdom Linear Coding (RLC), which is letting the detector assign a random weight *w_i* to (PV_*i*×payload_*i*), compute (*w_i*×PV_*i*×payload_*i*), and then sum the result together. We repeat this process *ḱ'* times for some *ḱ' >= ḱ*, so we get *ḱ'* equations. As long as at least *ḱ* of them are linearly independent, the recipient can decrypt the result assuming the detector sends back the weights (using a random seed).

### Improved Payload Retrieval (Section 6.3)
To reduce the computational cost of the server, instead of using RLC, we use sparse RLC. This means that only a small portion of the random weights are non-zero. The detailed arguments and analysis are relatively involved, so we omit the details here. Please see section 6.3 in our paper for details.

### Using PVW ciphertext as clue (Section 7.1)
Instead of using FHE ciphertext, we choose to use PVW ciphertext as clue to increase pracality, as [PVW](https://eprint.iacr.org/2007/348.pdf) ciphertext has size (*n* + ℓ) where *n* is the secret key dimension and it can be homomorphically decrypted relatively easily. The decryption circuit is designed based on this [paper](https://eprint.iacr.org/2021/1335.pdf).

### Using BFV homomorphic encryption (Section 7.2)
Since we do not need the recrypt operation, we can use leveled homomoprhic encryption instead of FHE to further reduce the computation cost. [B](https://eprint.iacr.org/2012/078)/[FV](https://eprint.iacr.org/2012/144) scheme is our choice, as it supports modular arithmetic on encrypted integers and SIMD-like operations. The PVW secret key is encrypted under BFV as well.

### Deterministic Digest Compression (Section 7.2)
Instead of using the randomized compression process as described above, we can compress the digest deterministically. Since each BFV ciphertext has *D* slots, where *D* is the ring dimentsion, and each slots performs operations on *Z_p*, we have *D×log(p)* bits in each ciphertext. Such compression gives us <5 bit/msg digest for index retrieval (compared to 926 bit/msg for the current solution used by Zcash). Of course, randomized digest compression is still better asymptotically, so for some parameters (e.g., *N* = 10,000,000, *ḱ* = 50), randomized digest compression is still prefered. The detailed comparisons are shown in Section 10 in our paper.

### Reducing Detection Key Size (Section 7.8)
The encryption of PVW secret key can be packed into a single BFV ciphertext (to achieve this, we redesigned the decryption circuit), which then reduces the detection key size from 13.5GB to ~2.6GB. We can use the seed mode in SEAL to further reduce it to ~1.3GB. This is still large and mainly due to the rotation keys of BFV. We can further reduce this cost by generating level-specific rotation keys. After the full compression, we now have detection key size of <130 MB for OMR1p and OMR2p, and of <100MB for OMD1p. Note that detection key is a one-time communication cost that doesn't need to be sent privately.

### Additional properties
DoS resistance (Section 8) and key-unlinkablity (Section 9) are both supported, where DoS resistance is supported inherantly and key-unlinkability requires application-specific changes.