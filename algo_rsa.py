import random
from sympy import isprime

def generate_prime_above(minimum):
    while True:
        num = random.randint(minimum + 1, 1000)
        if isprime(num):
            return num

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1

def mod_inverse(a, m):
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Inverse modulaire impossible")
    return x % m

def gen_key():
    p = generate_prime_above(100)
    q = generate_prime_above(100)
    n = p * q
    phi = (p - 1) * (q - 1)
    c = random.choice([3, 65537])  
    d = mod_inverse(c, phi)  
    return n, c, d

def create_characters():
    return {char: idx + 1 for idx, char in enumerate("abcdefghijklmnopqrstuvwxyz!?.' ")}

def encode_message(input_file, output_file, c, n):
    mapping = create_characters()
    with open(input_file, "r") as f:
        encoded_numbers = [
            pow(mapping[char], c, n) 
            for char in f.read() if char in mapping
        ]

    with open(output_file, "w") as f:
        f.writelines(f"{number}\n" for number in encoded_numbers)

def decode_message(input_file, output_file, d, n):
    reversed_mapping = {v: k for k, v in create_characters().items()}
    with open(input_file, "r") as f:
        decoded_message = "".join(
            reversed_mapping.get(pow(int(line.strip()), d, n), '') 
            for line in f.readlines()
        )

    with open(output_file, 'w') as f:
        f.write(decoded_message)

if __name__ == "__main__":
    n, c, d = gen_key()
    encode_message("code.txt", "code.num", c, n)
    decode_message("code.num", "decoded_message.txt", d, n)
