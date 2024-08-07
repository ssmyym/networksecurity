import numpy as np

# 매개변수 설정
n = 10  # 비밀 벡터의 차원
q = 97  # 모듈러에 사용할 소수
m = 15  # 샘플 수

def generate_secret(n, q):
    """비밀 벡터를 생성."""
    return np.random.randint(0, q, n)

def generate_error(m, q, scale=1):
    """오류 벡터 생성"""
    return np.random.normal(0, scale, m).astype(int) % q

def generate_public_key(secret, m, q):
    """공개 키 생성"""
    A = np.random.randint(0, q, (m, n))  # 랜덤하게 생성된 행렬 A
    e = generate_error(m, q)  # 오류 벡터 e
    b = (A @ secret + e) % q  # b = A * secret + e (모듈러 q)
    return A, b

def encrypt_bit(A, b, q, bit):
    """단일 비트 암호화."""
    r = np.random.randint(0, 2, A.shape[0])  # 랜덤한 이진 벡터 r
    u = r @ A % q  # u = r * A (모듈러 q)
    e = np.random.normal(0, 1)  # 암호화에 사용할 오류 항
    v = (r @ b + bit * (q // 2) + e) % q  # v = r * b + bit * (q/2) + e (모듈러 q)
    return u, v

def decrypt_bit(secret, u, v, q):
    """단일 비트를 복호화"""
    decrypted = (v - u @ secret) % q  # 복호화된 값 = v - u * secret (모듈러 q)
    # 복호화된 값을 0 또는 1로 해석
    if decrypted > q // 4 and decrypted < 3 * q // 4:
        return 1
    else:
        return 0

def string_to_binary(s):
    """문자열을 이진 표현으로 변환. 입력에 영어 외의 문자가 있는지 확인하고 예외를 발생"""
    for char in s:
        # 영어 알파벳과 숫자가 아닌 문자가 있으면 예외 발생
        if not ('A' <= char <= 'Z' or 'a' <= char <= 'z' or '0' <= char <= '9' or char in ' \n\t'):
            raise ValueError("입력에 영어 외의 문자가 포함되어 있습니다.")
    return ''.join(format(ord(c), '08b') for c in s)

def binary_to_string(b):
    """이진 표현을 다시 문자열로 변환"""
    return ''.join(chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8))

def encrypt_string(A, b, q, string):
    """문자열을 암호화"""
    binary_string = string_to_binary(string)  # 문자열을 이진 표현으로 변환
    encrypted_bits = [encrypt_bit(A, b, q, int(bit)) for bit in binary_string]  # 각 비트를 암호화
    return encrypted_bits

def decrypt_string(secret, encrypted_bits, q):
    """암호화된 비트 리스트를 복호화"""
    decrypted_bits = [decrypt_bit(secret, u, v, q) for u, v in encrypted_bits]  # 각 비트를 복호화
    binary_string = ''.join(map(str, decrypted_bits))  # 이진 문자열로 결합
    return binary_to_string(binary_string)  # 문자열로 변환

# 예제 사용법
secret = generate_secret(n, q)  # 비밀 벡터 생성
A, b = generate_public_key(secret, m, q)  # 공개 키 생성

try:
    # 사용자 입력
    user_input = input("암호화할 문자열을 입력하세요 (영어만 입력 가능): ")

    # 문자열 암호화
    encrypted_string = encrypt_string(A, b, q, user_input)
    print("암호화된 문자열:", encrypted_string)

    # 문자열 복호화
    decrypted_string = decrypt_string(secret, encrypted_string, q)
    print("복호화된 문자열:", decrypted_string)

except ValueError as e:
    print(e)
