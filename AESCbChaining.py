from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import math

# Function to encrypt data using AES
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv, ciphertext

# Function to decrypt data using AES
def decrypt_data(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode()

# Safe evaluation of expressions with math functions
def safe_eval(expr, allowed_locals=None):
    if allowed_locals is None:
        allowed_locals = {}
    allowed_locals.update({
        'math': math,
        '__builtins__': None
    })
    try:
        return eval(expr, {"__builtins__": None}, allowed_locals)
    except Exception as e:
        return f"Error evaluating calculation: {str(e)}"

# Function to perform calculations and encrypt the solutions
def calculate_and_encrypt(calculation, key):
    result = safe_eval(calculation)  # Use safe_eval to evaluate the calculation
    if isinstance(result, str) and result.startswith("Error"):  # If there was an error in eval
        return result, None
    result_str = str(result)  # Convert result to string
    iv, ciphertext = encrypt_data(result_str, key)  # Encrypt the result
    return iv, ciphertext

# Main function
def main():
    key = get_random_bytes(16)  # Generate a random 128-bit key

    calculations = [
        "3 + 5",
        "10 - 4",
        "6 * 7",
        "20 / 4",
        "2 ** 3",
        "25 ** 0.5",
        "math.log10(100)",
        "math.sin(math.pi / 2)",
        "abs(-8)",
        "0.2 * 50"
    ]

    encrypted_results = []

    for calc in calculations:
        iv, ciphertext = calculate_and_encrypt(calc, key)
        if iv is None:
            print(f"Error in calculation: {ciphertext}")
            continue
        encrypted_results.append((iv, ciphertext))

    # Print encrypted results
    for i, (iv, ciphertext) in enumerate(encrypted_results, 1):
        print(f"Calculation {i} encrypted:")
        print("IV:", iv.hex())
        print("Ciphertext:", ciphertext.hex())
        print()

if __name__ == "__main__":
    main()
