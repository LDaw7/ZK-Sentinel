# ZK-Sentinel: Privacy-Preserving Threat Detection

**Version:** 1.1.0  
**Licence:** MIT  
**Status:** Active Research Prototype

## Abstract
ZK-Sentinel is a hybrid intrusion detection system (IDS) designed to solve a specific problem in cyber warfare: verifying if an attacker matches a known Advanced Persistent Threat (APT) signature without storing sensitive threat intelligence on insecure edge devices.

The architecture decouples data collection from threat logic using an "Air-Gapped Logic Gate." The sensor ("The Eye") is a hardened C application that performs vectorisation, while the backend ("The Brain") utilises Homomorphic Encryption to calculate cosine similarity in the encrypted domain. This ensures that even if the sensor is compromised, the threat database remains cryptographically opaque to the attacker.

## Table of Contents
1. [Architecture](#architecture)
2. [Design Philosophy](#design-philosophy)
3. [Methodology](#methodology)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Compliance & Standards](#compliance--standards)

## Architecture

The system comprises two distinct components operating over a unidirectional data pipe.

### 1. The Eye (Sensor)
* **Language:** C (ISO C99)
* **Role:** Traffic ingestion and vectorisation.
* **Security Model:** Zero-Knowledge. The sensor holds no encryption keys and no signature database. It strictly converts raw input into a 2-dimensional feature vector (Hash, Length).

### 2. The Brain (Backend)
* **Language:** Python 3.9+
* **Library:** `python-paillier` (Partial Homomorphic Encryption)
* **Role:** Encrypted logic processing.
* **Algorithm:** Computes the normalised dot product between the live vector and the encrypted database to derive a similarity score without decrypting the source data.

## Design Philosophy

This project strictly adheres to safety-critical engineering principles often neglected in standard security tools. The rationale for these decisions is outlined below.

### British English Standardisation
All documentation, variable nomenclature, and comments utilise British English (e.g., `colour`, `serialise`, `behaviours`). This decision maintains consistency with UK-based academic and defence standards (e.g., NCSC guidelines) and ensures a unified linguistic tone throughout the codebase.

### The "Power of Ten" Rule Set
The C sensor is engineered in strict compliance with the NASA/JPL "Power of Ten" rules for safety-critical code. This ensures the sensor is deterministic and formally verifiable.
* **No Dynamic Allocation:** `malloc` and `free` are strictly forbidden to prevent memory leaks and heap fragmentation.
* **No Recursion:** Control flow is strictly linear or iterative to guarantee stack safety.
* **Fixed Loop Bounds:** All loops have a hard-coded upper limit to prevent "halting problem" scenarios or denial-of-service via infinite loops.

### Zero-Knowledge Architecture
Traditional honeypots store signature files locally (e.g., `known_bad_hashes.txt`). If an attacker gains root access to the honeypot, they can read this file to learn what the defenders know. ZK-Sentinel removes this vulnerability by performing the comparison in an encrypted state. $Enc(A) \cdot B$ is calculated, and only the scalar result is decrypted.

## Methodology

### Encrypted Cosine Similarity
Standard Cosine Similarity involves division, which is computationally expensive or impossible in many homomorphic cryptosystems. We mitigate this by pre-normalising all vectors to unit length (Magnitude = 1).

$$Similarity(A, B) = \frac{A \cdot B}{||A|| \times ||B||}$$

If $||A|| = 1$ and $||B|| = 1$, the equation simplifies to a standard Dot Product:

$$Similarity(A, B) = A \cdot B$$

The Paillier cryptosystem supports the addition of encrypted numbers and the multiplication of an encrypted number by a plaintext scalar. This allows us to compute the dot product of the encrypted signature database and the plaintext live vector:

$$Enc(Sim) = \sum (Enc(A_i) \times B_i)$$

## Installation

### Prerequisites
* GCC Compiler
* Python 3.9 or higher
* Make

### Build Instructions
The project uses a standard Makefile for compilation and dependency management.

```bash
# Clone the repository
git clone [https://github.com/LDaw7/ZK-Sentinel.git](https://github.com/LDaw7/ZK-Sentinel.git)
cd ZK-Sentinel

# Install Python dependencies and compile the C sensor
make all# ZK-Sentinel
