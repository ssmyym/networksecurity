import socket
import traceback
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
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
    ).rstrip(b'\n')  # Remove trailing newline to avoid issues during transmission.
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
    ).rstrip(b'\n')  # Remove trailing newline to avoid issues during transmission.
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
    # Create a TCP/IP socket.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow the reuse of local addresses.
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind the socket to the server address and port.
    server_socket.bind(('127.0.0.1', 8081))
    # Listen for incoming connections.
    server_socket.listen()

    print('Server listening on 127.0.0.1:8081')

    # Accept a connection from a client.
    conn, addr = server_socket.accept()
    print(f'Connected by {addr}')

    try:
        # Generate RSA key pair for the server.
        server_rsa_private_key, server_rsa_public_key_pem = generate_rsa_key_pair()
        print("Server RSA Public Key PEM:", server_rsa_public_key_pem.decode())

        # Send the server's RSA public key to the client.
        conn.sendall(server_rsa_public_key_pem)

        # Receive the client's RSA public key.
        client_rsa_public_key_pem = conn.recv(4096)
        print("Received Client RSA Public Key PEM:", client_rsa_public_key_pem.decode())
        client_rsa_public_key = serialization.load_pem_public_key(client_rsa_public_key_pem, backend=default_backend())

        # Generate and send Diffie-Hellman parameters (p, g) to the client.
        dh_parameters = generate_dh_parameters()
        p = dh_parameters.parameter_numbers().p
        g = dh_parameters.parameter_numbers().g
        conn.sendall(p.to_bytes(256, 'big') + g.to_bytes(256, 'big'))
        print("Sent DH Parameters (p, g)")

        # Generate DH key pair for the server and serialize the public key.
        server_dh_private_key, server_dh_public_key_pem = generate_dh_key_pair(dh_parameters)
        print("Server DH Public Key PEM:", server_dh_public_key_pem.decode())

        # Sign the DH public key using the server's RSA private key.
        signature = sign_message(server_rsa_private_key, server_dh_public_key_pem)
        print("Signature:", signature.hex())

        # Send the DH public key and the signature to the client.
        conn.sendall(server_dh_public_key_pem + signature)
        print("Sent DH Public Key and Signature")

        # Receive the client's DH public key and signature.
        client_dh_public_key_bytes = conn.recv(4096)
        client_dh_public_key_pem = client_dh_public_key_bytes[
                                   :client_dh_public_key_bytes.find(b'-----END PUBLIC KEY-----') + len(
                                       b'-----END PUBLIC KEY-----')]
        print("Received Client DH Public Key PEM:", client_dh_public_key_pem.decode())

        # Extract the client's signature.
        client_signature = client_dh_public_key_bytes[client_dh_public_key_bytes.find(b'-----END PUBLIC KEY-----') + len(b'-----END PUBLIC KEY-----'):]
        print("Client Signature:", client_signature.hex())

        try:
            # Deserialize the client's DH public key.
            client_dh_public_key = serialization.load_pem_public_key(client_dh_public_key_pem, backend=default_backend())
        except Exception as e:
            # Print detailed error information if deserialization fails.
            print("Failed to deserialize client's DH public key:")
            print("Detailed Exception Information:")
            traceback.print_exc()
            return

        # Verify the client's DH public key signature using the client's RSA public key.
        if not verify_signature(client_rsa_public_key, client_dh_public_key_pem, client_signature):
            print('Failed to verify client DH public key signature.')
            return

        # Send back the client's DH public key to the client.
        conn.sendall(client_dh_public_key_pem.rstrip(b'\n'))
        print("Sent back Client DH Public Key PEM to Client")

        # Generate a shared key using the server's DH private key and the client's DH public key.
        shared_key = server_dh_private_key.exchange(client_dh_public_key)
        session_key = generate_session_key(shared_key)
        print(f'Shared Key: {session_key.hex()}')

        while True:
            data = conn.recv(4096)
            if not data:
                break
            encrypted_message = data
            # Decrypt the received encrypted message.
            decrypted_message = decrypt_message(session_key, encrypted_message).decode()
            print(f"Received encrypted message: {encrypted_message.hex()}")
            print(f"Decrypted message: {decrypted_message}")
            if decrypted_message.lower() == 'bye':
                print("Client requested to end the connection.")
                break

    except Exception as e:
        # Print detailed error information if any exception occurs.
        print(f'An error occurred: {e}')
        traceback.print_exc()

    finally:
        # Close the connection.
        conn.close()

if __name__ == '__main__':
    main()
