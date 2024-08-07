import socket
import traceback
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generate_rsa_key_pair():
    # Generate a new RSA private key.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    private_key = key
    # Extract the public key from the private key.
    public_key = key.public_key()
    # Serialize the public key to PEM format.
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).rstrip(b'\n')
    return private_key, public_key_bytes

def generate_dh_parameters():
    # Generate Diffie-Hellman parameters for key exchange.
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

def generate_dh_key_pair(parameters):
    # Generate a DH private key using provided parameters.
    private_key = parameters.generate_private_key()
    # Serialize the public key to PEM format.
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).rstrip(b'\n')
    return private_key, public_key

def sign_message(private_key, message):
    # Sign a message using the private key and PSS padding scheme.
    signature = private_key.sign(
        message,
        PSS(
            mgf=MGF1(hashes.SHA256()),
            salt_length=PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    try:
        # Verify a signature using the public key.
        public_key.verify(
            signature,
            message,
            PSS(
                mgf=MGF1(hashes.SHA256()),
                salt_length=PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        # Print detailed error information if verification fails.
        print(f"Signature verification failed: {e}")
        print("Detailed Exception Information:")
        traceback.print_exc()
        print("Public Key:", public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode())
        print("Message:", message)
        print("Signature:", signature.hex())
        return False

def generate_session_key(shared_key):
    # Derive a session key from the shared DH key using HKDF.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'session_key',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

def encrypt_message(key, plaintext):
    # Encrypt a plaintext message using AES in CFB mode.
    iv = os.urandom(16)  # Generate a random IV.
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext  # Prepend IV to ciphertext.

def decrypt_message(key, ciphertext):
    # Decrypt a ciphertext message using AES in CFB mode.
    iv = ciphertext[:16]  # Extract IV from the beginning.
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 8081))  # Connect to the server.

    try:
        # Generate RSA key pair for the client.
        client_rsa_private_key, client_rsa_public_key_pem = generate_rsa_key_pair()
        print("Client RSA Public Key PEM:", client_rsa_public_key_pem.decode())

        # Receive the server's RSA public key.
        server_rsa_public_key_pem = client_socket.recv(4096)
        print("Received Server RSA Public Key PEM:", server_rsa_public_key_pem.decode())
        server_rsa_public_key = serialization.load_pem_public_key(server_rsa_public_key_pem, backend=default_backend())

        # Send the client's RSA public key to the server.
        client_socket.sendall(client_rsa_public_key_pem)

        # Receive DH parameters (p, g) from the server.
        p_g = client_socket.recv(512)
        p = int.from_bytes(p_g[:256], 'big')
        g = int.from_bytes(p_g[256:], 'big')
        dh_parameters = dh.DHParameterNumbers(p, g).parameters(default_backend())
        print("Received DH Parameters (p, g)")

        # Generate DH key pair for the client and serialize the public key.
        client_dh_private_key, client_dh_public_key_pem = generate_dh_key_pair(dh_parameters)
        print("Client DH Public Key PEM:", client_dh_public_key_pem.decode())

        # Sign the DH public key using the client's RSA private key.
        signature = sign_message(client_rsa_private_key, client_dh_public_key_pem)
        print("Signature:", signature.hex())

        # Send the DH public key and the signature to the server.
        client_socket.sendall(client_dh_public_key_pem + signature)

        # Receive the server's DH public key and signature.
        server_dh_public_key_bytes = client_socket.recv(4096)
        server_dh_public_key_pem = server_dh_public_key_bytes[
                                   :server_dh_public_key_bytes.find(b'-----END PUBLIC KEY-----') + len(
                                       b'-----END PUBLIC KEY-----')]
        print("Received Server DH Public Key PEM:", server_dh_public_key_pem.decode())
        server_dh_public_key = serialization.load_pem_public_key(server_dh_public_key_pem, backend=default_backend())

        # Extract the server's signature.
        server_signature_start = server_dh_public_key_bytes.find(b'-----END PUBLIC KEY-----') + len(
            b'-----END PUBLIC KEY-----')
        server_signature = server_dh_public_key_bytes[server_signature_start:]
        print("Server Signature:", server_signature.hex())

        # Verify the server's DH public key signature using the server's RSA public key.
        if not verify_signature(server_rsa_public_key, server_dh_public_key_pem, server_signature):
            print('Failed to verify server DH public key signature.')
            return

        # Receive back the client's DH public key from the server.
        returned_client_dh_public_key_pem = client_socket.recv(4096)
        print("Received back Client DH Public Key PEM from Server:", returned_client_dh_public_key_pem.decode())

        # Compare the received DH public key with the original one.
        if client_dh_public_key_pem == returned_client_dh_public_key_pem.rstrip(b'\n'):
            print("Client DH Public Key PEM matches with the one sent to the Server.")
        else:
            print("Client DH Public Key PEM does not match.")
            for i in range(min(len(client_dh_public_key_pem), len(returned_client_dh_public_key_pem))):
                if client_dh_public_key_pem[i] != returned_client_dh_public_key_pem[i]:
                    print(f"Difference at byte {i}: {client_dh_public_key_pem[i]} != {returned_client_dh_public_key_pem[i]}")
            if len(client_dh_public_key_pem) != len(returned_client_dh_public_key_pem):
                print("Lengths are different:")
                print(f"Original length: {len(client_dh_public_key_pem)}, Returned length: {len(returned_client_dh_public_key_pem)}")

        # Generate a shared key using the client's DH private key and the server's DH public key.
        shared_key = client_dh_private_key.exchange(server_dh_public_key)
        session_key = generate_session_key(shared_key)
        print(f'Shared Key: {session_key.hex()}')

        while True:
            message = input("Enter message: ")
            encrypted_message = encrypt_message(session_key, message.encode())
            client_socket.sendall(encrypted_message)  # Send the encrypted message to the server.
            print(f"Sent encrypted message: {encrypted_message.hex()}")
            if message.lower() == 'bye':
                print("Ending the connection.")
                break

    except Exception as e:
        # Print detailed error information if any exception occurs.
        print(f'An error occurred: {e}')
        traceback.print_exc()

    finally:
        # Close the socket connection.
        client_socket.close()

if __name__ == '__main__':
    main()
