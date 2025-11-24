"""
Project: ZK-Sentinel (The Brain)
Description: Privacy-Preserving Threat Detection using Homomorphic Encryption.
Logic: Computes Cosine Similarity between Encrypted Signatures and Plaintext Live Vectors.
"""

import sys
import json
import math
import numpy as np
from phe import paillier

# 1. Configuration: Known "APT" Signatures (Pre-calculated vectors)
# Example: 'rm -rf /' might hash to [vector_val1, vector_val2]
KNOWN_SIGNATURES = {
    "APT_GROUP_A": np.array([123456789, 15]), # [Hash, Length]
    "ROOTKIT_INSTALL": np.array([987654321, 20])
}

def normalize_vector(v):
    """Normalize vector to unit length (Magnitude = 1)."""
    norm = np.linalg.norm(v)
    if norm == 0: 
        return v
    return v / norm

def main():
    print("[*] Initializing ZK-Sentinel Brain...", file=sys.stderr)
    
    # 2. Key Generation (The "Secret" Environment)
    print("[*] Generating Paillier Keypair (2048-bit)...", file=sys.stderr)
    public_key, private_key = paillier.generate_paillier_keypair()
    
    # 3. Encrypt the Database (This usually happens once and is stored)
    print("[*] Encrypting Threat Database...", file=sys.stderr)
    encrypted_db = {}
    
    for name, vec in KNOWN_SIGNATURES.items():
        # Normalize FIRST for Cosine Similarity trick
        norm_vec = normalize_vector(vec)
        # Encrypt each component of the vector
        encrypted_vec = [public_key.encrypt(float(x)) for x in norm_vec]
        encrypted_db[name] = encrypted_vec
        
    print("[+] Database Encrypted. Private Key stays here.", file=sys.stderr)
    print("[*] Listening for Sensor Input (stdin)...", file=sys.stderr)

    # 4. Processing Loop
    for line in sys.stdin:
        try:
            data = json.loads(line)
            # Incoming vector from C Sensor: [Hash, Length]
            live_vector = np.array(data["v"])
            
            # Normalize the live vector (Plaintext)
            live_norm = normalize_vector(live_vector)
            
            print(f"\n[>] Analyzing Vector: {live_vector}", file=sys.stderr)

            # 5. Zero-Knowledge Detection
            # We compute Dot Product(Encrypted_Sig, Plain_Live)
            # Result = Encrypted(Similarity_Score)
            
            for threat_name, enc_sig_vec in encrypted_db.items():
                # Homomorphic Dot Product: Sum(Enc(A) * b)
                # phe library supports EncryptedNumber * Scalar
                
                enc_dot_product = 0
                for i in range(len(enc_sig_vec)):
                    enc_dot_product += enc_sig_vec[i] * live_norm[i]
                
                # In a true Zero-Knowledge architectures, this 'enc_dot_product' 
                # would be sent to a third party to decrypt. 
                # Here, we decrypt locally to alert.
                
                similarity = private_key.decrypt(enc_dot_product)
                
                print(f"   - Similarity to {threat_name}: {similarity:.4f}", file=sys.stderr)
                
                if similarity > 0.99:
                    print(f"   [!!!] ALERT: MATCH FOUND FOR {threat_name}", file=sys.stderr)

        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"[!] Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()