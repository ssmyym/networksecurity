import random
import math

# 밀러-라빈 소수 판별 알고리즘
def is_prime(n, k=5):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # n-1 = 2^s * d 형태로 변환합니다.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # 소수 판별을 k회 반복합니다.
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

## 확장된 유클리드 알고리즘
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

# 소수 p, q를 생성합니다.
def generate_primenumber():
    p, q = map(int, input('Enter the prime number').split())
    while(True):
        if is_prime(p) == False or is_prime(q) == False:
            print('Please enter prime numbers')
            p, q = map(int, input('Enter the prime number').split())
        elif p == q:
            print('Please enter two different prime numbers')
            p, q = map(int, input('Enter the prime number').split())
        else:
            break
    return p, q

# RSA 키를 생성합니다.
def generate_keys():
    p,q = generate_primenumber()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi) # 1 < e < φ(n)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    d = mod_inverse(e, phi)
    print('moduler:d ',d)
    return ((e, n), (d, n))

# 문자열을 정수로 변환합니다.
def string_to_int(message):
    message_int = 0
    for char in message:
        message_int = message_int * 256 + ord(char)
    return message_int

# 정수를 문자열로 변환합니다.
def int_to_string(message_int):
    message = ""
    while message_int:
        message = chr(message_int % 256) + message
        message_int //= 256
    return message

# 메시지를 암호화합니다.
def encrypt(message, public_key):
    e, n = public_key
    encrypted_message = []
    for char in message:
        if char != ' ':
            encrypted_char = pow(ord(char), e, n)
            encrypted_message.append(encrypted_char)
    return encrypted_message

# 메시지를 복호화합니다.
def decrypt(ciphertext, private_key):
    d, n = private_key
    decrypted_message = ""
    for encrypted_char in ciphertext:
        decrypted_char = pow(encrypted_char, d, n)
        decrypted_message += chr(decrypted_char)
    return decrypted_message

def main():
    # RSA 키 생성
    public_key, private_key = generate_keys()

    print("Public Key:", public_key)
    print("Private Key:", private_key)

    # 사용자로부터 메시지 입력
    message = input("Enter a message: ")

    # 메시지 암호화
    encrypted_message = encrypt(message, public_key)
    print("Encrypted message:", encrypted_message)

    # 암호문 복호화
    decrypted_message = decrypt(encrypted_message, private_key)
    print("Decrypted message:", decrypted_message)


if __name__ == "__main__":
    main()
