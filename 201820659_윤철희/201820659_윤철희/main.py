import random
from math import isqrt
import hashlib
import hmac
from ecc import Point,FieldElement
import libnum

def derive_keys(T):
        tx, ty = T.x, T.y

        tx_binary = bin(tx.num)[2:]

        tx_binary_cropped = tx_binary[0:192]

        tx_restored = int(tx_binary_cropped, 2)

        hash_hex = hashlib.sha256(str.encode(str(tx_restored))).hexdigest()
        hash_binary = bin(int(hash_hex, 16))[2:]
        ## bit를 slicing해서 ECIES 부분과 MAC 부분에 같은 key를 사용하지 않게한다.
        k1 = int(hash_binary[0:128], 2).to_bytes(16, byteorder='big')
        k2 = int(hash_binary[128:],2).to_bytes(16, byteorder='big')

        return k1, k2

def find_mac(message, key):
        return hmac.new(key,message, hashlib.sha256).hexdigest()

def pad(data):
        """
        PKCS#7 패딩을 사용하여 데이터를 패딩
        """
        block_size = 16  # AES 블록 크기는 16바이트
        padding_length = block_size - len(data) % block_size
        padding = bytes([padding_length] * padding_length)
        return data + padding


def unpad(data, block_size=16):
        pad = data[-1]
        if pad < 1 or pad > block_size:
            raise ValueError("Invalid pad value")
        return data[:-pad]

def aes_encrypt(plaintext, key):
        # AES 암호화
        ciphertext = bytearray(plaintext)
        for i in range(len(plaintext)):
            # 키의 길이가 블록 크기보다 짧을 경우, 키를 순환하여 사용
            ciphertext[i] ^= key[i % len(key)]
        return bytes(ciphertext)

def aes_decrypt(ciphertext, key):
        # AES 복호화는 암호화와 동일하므로 동일한 함수 사용
        return aes_encrypt(ciphertext, key)


# a,b 값에 따른 변하는 생성점 G (Gx,Gy) 값을 구하는 함수
def base_point(a, b, p):
    start = 900
    x = start
    count = 0
    while True:
        val = ((x * x * x) + a * x + b) % p
        if (val == 0):
            print(x, "0")
            count = count + 1

        rtn = libnum.jacobi(val, p)

        if (rtn == 1):
            res = next(libnum.sqrtmod(val, {p: 1}))
            print("(", x, int(res), ")", end='')
            print("(", x, int(p - res), ")", end='')
            count = count + 2
            if count == 2:  # Gx와 Gy 값을 찾았으면 바로 반환
                return x, res
        x = x + 1

        if (count > 50 or x == p): return count
        if (x - start > 400): return count
    print(a, b)

    return x, isqrt(val)

def main():

        # y^2 = x^3 + ax + b -> secp256k1 타원 곡선의 파라미터
        # secp256k1 타원 곡선의 생성점
        a, b, p = map(int, input('Enter the a, b, p: ').split())

        # Generator point (Gx, Gy)
        # secp256k1 타원 곡선의 생성점 구하기 base_point에 random 한 값으로 넣을 경우 curve를 생성하지 못하는 경우가 발생 :
        # 강의노트 처럼 a = 324 b =1287 p =3851 일 경우 암복호화 까지 잘진행
        Gx, Gy = base_point(a, b, p)

        a = FieldElement(a,p)
        b = FieldElement(b,p)
        Gx = FieldElement(Gx,p)
        Gy = FieldElement(Gy,p)
        G = Point(Gx,Gy,a,b)

        # random 한 값으로 private key 생성  ECDH 방식으로 key 교환 forward security을 만족 시킴
        # Rsa로 교환 할 경우 Ks 값이 변하지 않음으로 forward security을 만족못함
        Alice_private_key = random.randint(1,p-1)
        Bob_private_key = random.randint(1, p-1)

        U = Alice_private_key * G
        B = Bob_private_key * G

        print("Shared Key (U.x, U.y):", U.x, U.y)
        print("Shared Key (B.x, B.y):", B.x, B.y)

        k1,k2 = derive_keys(U)

        # ECDHE를 통해 공유된 키 계산
        shared_key = Alice_private_key * B
        shared_key_bytes = shared_key.x.num.to_bytes(32, 'big')

        plaintext = input("Enter the plaintext: ")

        # AES을 통해 평문을 암호화
        encrypted_data = aes_encrypt(plaintext.encode(), k1)
        print("Encrypted message:", encrypted_data)

        # 암호문을 복호화
        decrypted_data = aes_decrypt(encrypted_data, k1)
        print("Decrypted message:", decrypted_data.decode())

if __name__ == "__main__":
        main()
