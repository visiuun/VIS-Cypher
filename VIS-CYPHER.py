import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidKey, AlreadyFinalized, InvalidTag,  UnsupportedAlgorithm # Simplified exception import
import time  # For optional timing measurements

# --- VIS-Cipher: Advanced Demonstration ---
# This is an enhanced demonstration of a secure encryption system, building upon VIS-Cipher.
# It aims to address more practical aspects, error handling, and security considerations.
# HOWEVER, it is still a demonstration and MUST NOT be used for real-world sensitive data without
# thorough security review by cryptography experts.  "Best in everything" is not achievable
# without rigorous analysis and community vetting over time.

def vis_generate_key_advanced(password, salt=None, iterations=150000, key_length_bytes=32, hash_algorithm=hashes.SHA256()):
    """
    Generates a secure encryption key from a password using PBKDF2HMAC.

    Args:
        password (str): The user's password.
        salt (bytes, optional): A pre-existing salt (for decryption). If None, a new salt is generated for encryption.
        iterations (int): Number of PBKDF2 iterations (higher is more secure but slower). Default: 150000 (increased for better security).
        key_length_bytes (int): Length of the derived key in bytes. Default: 32 (256-bit for AES-256).
        hash_algorithm (hashes.HashAlgorithm): Hash algorithm for PBKDF2. Default: SHA256.

    Returns:
        tuple: (key, salt) - key (bytes) is the derived encryption key, salt (bytes) is the salt used.
               Returns None, None and prints an error message if key derivation fails.
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt if not provided

    try:
        kdf = PBKDF2HMAC(
            algorithm=hash_algorithm,
            length=key_length_bytes,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
    except Exception as e: # Catch potential exceptions during key derivation
        print(f"Error during key derivation: {e}")
        return None, None

def vis_encrypt_advanced(plaintext, password):
    """
    Encrypts plaintext using VIS-Cipher Advanced (AES-256-GCM).

    Args:
        plaintext (str or bytes): The plaintext to encrypt (can be string or bytes).
        password (str): The password to use for encryption.

    Returns:
        dict or None: A dictionary containing encrypted data (salt, iv, ciphertext, tag) as base64 strings,
                     or None if encryption fails.
    """
    if not isinstance(plaintext, (str, bytes)):
        print("Error: Plaintext must be a string or bytes.")
        return None
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode('utf-8') # Encode string to bytes for encryption
    else:
        plaintext_bytes = plaintext # Already bytes

    key, salt = vis_generate_key_advanced(password)
    if key is None: # Key generation failed
        return None

    iv = os.urandom(16)  # Generate a random IV for each encryption

    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext_bytes) + padder.finalize()

        ciphertext_bytes = encryptor.update(padded_plaintext) + encryptor.finalize()
        tag = encryptor.tag  # GCM tag for authentication

        encrypted_data = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext_bytes).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }
        return encrypted_data

    except InvalidKey:
        print("Error: Invalid encryption key.") # Should not happen normally, but for robustness
        return None
    except AlreadyFinalized:
        print("Error: Cipher object was used multiple times incorrectly.") # Programming error, should not happen in this code
        return None
    except NotReady:
        print("Error: Cipher object not ready for encryption.") # Programming error
        return None
    except UnsupportedAlgorithm:
        print("Error: Algorithm not supported by backend.") # Should not happen with AES/GCM in cryptography lib
        return None
    except Exception as e: # Catch any other unexpected exceptions during encryption
        print(f"An unexpected error occurred during encryption: {e}")
        return None

def vis_decrypt_advanced(encrypted_data, password):
    """
    Decrypts ciphertext using VIS-Cipher Advanced (AES-256-GCM).

    Args:
        encrypted_data (dict): Dictionary containing encrypted data (salt, iv, ciphertext, tag) as base64 strings.
        password (str): The password used for encryption.

    Returns:
        bytes or None: The decrypted plaintext as bytes,
                             or None if decryption fails (authentication failure, invalid data, etc.).
    """
    try:
        salt = base64.b64decode(encrypted_data['salt'])
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext_bytes = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])
    except KeyError as e:
        print(f"Error: Missing key in encrypted data: {e}")
        return None
    except base64.binascii.Error:
        print("Error: Invalid base64 encoded data in encrypted data.")
        return None


    key, _ = vis_generate_key_advanced(password, salt=salt) # Re-derive key using stored salt
    if key is None: # Key derivation failed (should not happen if salt is valid)
        return None

    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()) # Pass tag for authentication
        decryptor = cipher.decryptor()

        decrypted_padded_bytes = decryptor.update(ciphertext_bytes) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext_bytes = unpadder.update(decrypted_padded_bytes) + unpadder.finalize()

        return plaintext_bytes  # Directly return the decrypted bytes - caller handles string decoding if needed

    except InvalidKey:
        print("Error: Invalid decryption key (incorrect password or corrupted key).") # Incorrect password is a likely cause
        return None
    except InvalidTag: # GCM authentication tag verification failed - data was tampered with or incorrect password
        print("Error: Authentication failed! Data may be corrupted or tampered with, or incorrect password.")
        return None
    except AlreadyFinalized:
        print("Error: Cipher object was used multiple times incorrectly (decryption).") # Programming error
        return None
    except NotReady:
        print("Error: Cipher object not ready for decryption.") # Programming error
        return None
    except UnsupportedAlgorithm:
        print("Error: Algorithm not supported by backend (decryption).") # Should not happen with AES/GCM
        return None
    except Exception as e: # Catch any other unexpected exceptions during decryption
        print(f"An unexpected error occurred during decryption: {e}")
        return None


# --- Advanced Example Usage and Demonstrations ---
if __name__ == "__main__":
    password = "mySuperSecretPassword123" # *** IMPORTANT: Use a strong, randomly generated password in real applications! ***
    plaintext_string = "This is a secret message to be encrypted with VIS-Cipher Advanced.  We are testing string plaintext."
    plaintext_bytes = b"This is secret binary data to be encrypted with VIS-Cipher Advanced. We are testing byte plaintext." #(or "plaintext_string.encode('utf-8')")

    print("--- String Plaintext Encryption/Decryption ---")
    start_time_string_enc = time.perf_counter()
    encrypted_string_data = vis_encrypt_advanced(plaintext_string, password)
    end_time_string_enc = time.perf_counter()

    if encrypted_string_data:
        print("Encrypted String Data:", encrypted_string_data)
        start_time_string_dec = time.perf_counter()
        decrypted_string_plaintext_bytes = vis_decrypt_advanced(encrypted_string_data, password) # Decryption returns bytes now
        decrypted_string_plaintext = decrypted_string_plaintext_bytes.decode('utf-8') # Decode bytes to string for string plaintext
        end_time_string_dec = time.perf_counter()

        if decrypted_string_plaintext == plaintext_string:
            print("Decrypted String Plaintext:", decrypted_string_plaintext)
            print("\nString Encryption and Decryption successful!")
            print(f"String Encryption Time: {(end_time_string_enc - start_time_string_enc):.4f} seconds")
            print(f"String Decryption Time: {(end_time_string_dec - start_time_string_dec):.4f} seconds")
        else:
            print("Decrypted String Plaintext:", decrypted_string_plaintext) # Might print 'None' if decryption failed
            print("\nError: String Decryption failed! (Content mismatch)")
    else:
        print("\nError: String Encryption failed!")


    print("\n--- Bytes Plaintext Encryption/Decryption ---")
    start_time_bytes_enc = time.perf_counter()
    encrypted_bytes_data = vis_encrypt_advanced(plaintext_bytes, password)
    end_time_bytes_enc = time.perf_counter()

    if encrypted_bytes_data:
        print("Encrypted Bytes Data:", encrypted_bytes_data)
        start_time_bytes_dec = time.perf_counter()
        decrypted_bytes_plaintext = vis_decrypt_advanced(encrypted_bytes_data, password) # Decryption returns bytes
        end_time_bytes_dec = time.perf_counter()

        if decrypted_bytes_plaintext == plaintext_bytes: # Compare bytes directly
            print("Decrypted Bytes Plaintext:", decrypted_bytes_plaintext) # Print raw bytes directly
            print("\nBytes Encryption and Decryption successful!")
            print(f"Bytes Encryption Time: {(end_time_bytes_enc - start_time_bytes_enc):.4f} seconds")
            print(f"Bytes Decryption Time: {(end_time_bytes_dec - start_time_bytes_dec):.4f} seconds")
        else:
            print("Decrypted Bytes Plaintext:", decrypted_bytes_plaintext) # Might print 'None' or bytes if decryption failed
            print("\nError: Bytes Decryption failed! (Content mismatch)")
    else:
        print("\nError: Bytes Encryption failed!")


    print("\n--- Demonstration of Authentication Failure (Tampering) ---")
    if encrypted_string_data:
        tampered_data = encrypted_string_data.copy()
        tampered_data['ciphertext'] = base64.b64encode(os.urandom(len(base64.b64decode(tampered_data['ciphertext'])))).decode('utf-8') # Replace ciphertext with random data
        print("\nAttempting to decrypt tampered data...")
        decrypted_tampered_plaintext = vis_decrypt_advanced(tampered_data, password)
        if decrypted_tampered_plaintext is None:
            print("Authentication failure correctly detected on tampered data! Decryption returned None as expected.")
        else:
            print("Error: Authentication failure NOT detected! Decryption of tampered data succeeded unexpectedly:", decrypted_tampered_plaintext) # This SHOULD NOT happen

    print("\n--- Demonstration of Incorrect Password ---")
    if encrypted_string_data:
        incorrect_password = "wrongPassword"
        print("\nAttempting decryption with incorrect password...")
        decrypted_wrong_password = vis_decrypt_advanced(encrypted_string_data, incorrect_password)
        if decrypted_wrong_password is None:
            print("Decryption with incorrect password failed as expected! Decryption returned None.")
        else:
            print("Error: Decryption with incorrect password succeeded unexpectedly:", decrypted_wrong_password) # This SHOULD NOT happen

    print("\n--- Security Warning ---")
    print("\n*** SECURITY WARNING! ***")
    print("VIS-Cipher Advanced is a DEMONSTRATION for educational purposes.")
    print("It is NOT a replacement for thoroughly vetted and standardized cryptographic libraries and protocols.")
    print("DO NOT use this code for real-world sensitive data without expert cryptographic review.")
    print("Password-based encryption has inherent limitations.  Strong key management practices are crucial for real security.")
    print("For production systems, use well-established libraries (like cryptography in Python) and follow security best practices.")
    print("Consider side-channel attack resistance, post-quantum cryptography, and robust key exchange mechanisms for advanced security needs.")
