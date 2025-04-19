import ctypes
import os
import sys
# Add the path to the Python AES implementation
import sys, os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import random
import platform
import subprocess

# Import the Python AES functions for comparison
try:
    from aes import sub_bytes as py_sub_bytes, inv_sub_bytes as py_inv_sub_bytes
    from aes import shift_rows as py_shift_rows, inv_shift_rows as py_inv_shift_rows
    from aes import mix_columns as py_mix_columns, inv_mix_columns as py_inv_mix_columns
    from aes import add_round_key as py_add_round_key
    from aes import AES, bytes2matrix, matrix2bytes
except ImportError:
    from aes import sub_bytes as py_sub_bytes, inv_sub_bytes as py_inv_sub_bytes
    from aes import shift_rows as py_shift_rows, inv_shift_rows as py_inv_shift_rows
    from aes import mix_columns as py_mix_columns, inv_mix_columns as py_inv_mix_columns
    from aes import add_round_key as py_add_round_key
    from aes import AES, bytes2matrix, matrix2bytes

# Load the compiled C library
# Determine platform-specific library name
if platform.system() == "Windows":
    lib_name = "rijndael.dll"
elif platform.system() == "Darwin":
    lib_name = "rijndael.dylib"
else:
    lib_name = "rijndael.so"
# Auto-compile the C file if the shared library doesn't exist
if not os.path.exists(lib_name):
    print(f"[INFO] {lib_name} not found — compiling rijndael.c")
    try:
        if platform.system() == "Windows":
            compile_cmd = ["gcc", "-shared", "-o", "rijndael.dll", "rijndael.c"]
        else:
            # For Linux and macOS
            compile_cmd = ["gcc", "-shared", "-fPIC", "-o", lib_name, "rijndael.c"]
        subprocess.run(compile_cmd, check=True)
        print(f"[INFO] Compilation successful.")
    except subprocess.CalledProcessError:
        print(f"[ERROR] Failed to compile rijndael.c.")
        sys.exit(1)
# Now load the shared library
try:
    rijndael = ctypes.CDLL(f"./{lib_name}")
except OSError as e:
    print(f"[ERROR] Failed to load shared library: {e}")
    sys.exit(1)

# Function to expand key in Python
def py_expand_key(key_bytes):
    aes = AES(key_bytes)
    expanded = []
    for matrix in aes._key_matrices:
        for row in matrix:
            for byte in row:
                expanded.append(byte)
    return bytes(expanded)

# Generic test runner for most AES transformation functions
def test_function(func_name, c_func, py_func, conversions=True):
    print(f"Testing {func_name}")
    
    for i in range(3):
        # Generate random 16-byte input
        input_data = bytearray(random.randint(0, 255) for _ in range(16))
        
        # For add_round_key we also need a second key input
        if func_name == "add_round_key":
            key_data = bytearray(random.randint(0, 255) for _ in range(16))
            key_matrix = bytes2matrix(key_data)
        
        # Convert to matrix for Python version
        py_matrix = bytes2matrix(input_data) if conversions else bytes(input_data)
        
        # Apply Python function
        if func_name == "add_round_key":
            py_func(py_matrix, key_matrix)
        else:
            py_func(py_matrix)
        
        # Convert Python result back to bytes
        py_result = matrix2bytes(py_matrix) if conversions else py_matrix

        # Prepare C input
        c_input = ctypes.create_string_buffer(bytes(input_data), 16)
        
        # Call C function
        if func_name == "add_round_key":
            c_key = ctypes.create_string_buffer(bytes(key_data), 16)
            c_func(c_input, c_key)
        else:
            c_func(c_input)
        
        # Extract C result
        c_result = bytearray(c_input.raw)
        
        # Compare results
        if py_result == c_result:
            print(f"  Test {i+1}: PASSED")
        else:
            print(f"  Test {i+1}: FAILED")
            print(f"  Python result: {list(py_result)}")
            print(f"  C result: {list(c_result)}")

# ShiftRows functions need special treatment because they operate across rows
# Now that we're using row-major layout in C, we can skip the transposition step
def test_shift_rows_function(func_name, c_func, py_func):
    print(f"Testing {func_name}")
    
    for i in range(3):
        # Generate random input
        input_bytes = bytearray(random.randint(0, 255) for _ in range(16))

        # Python version
        py_input = input_bytes.copy()
        py_matrix = bytes2matrix(py_input)
        py_func(py_matrix)
        py_result = matrix2bytes(py_matrix)

        # C version — just use row-major directly now
        c_input = ctypes.create_string_buffer(bytes(input_bytes), 16)
        c_func(c_input)
        c_result = bytearray(c_input.raw)

        # Compare
        if py_result == c_result:
            print(f"  Test {i+1}: PASSED")
        else:
            print(f"  Test {i+1}: FAILED")
            print(f"  Python result: {list(py_result)}")
            print(f"  C result: {list(c_result)}")

# Test the key expansion output (Python vs. C)
def test_key_expansion():
    print("Testing expand_key")
    
    rijndael.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte * 176)
    
    for i in range(3):
        key = bytearray(random.randint(0, 255) for _ in range(16))
        py_result = py_expand_key(key)
        
        c_key = ctypes.create_string_buffer(bytes(key), 16)
        c_result_ptr = rijndael.expand_key(c_key)
        c_result = bytearray(c_result_ptr.contents)

        if py_result == c_result:
            print(f"  Test {i+1}: PASSED")
        else:
            print(f"  Test {i+1}: FAILED")
            for j in range(11):
                start = j * 16
                end = start + 16
                print(f"  Round {j}:")
                print(f"    Python: {list(py_result[start:end])}")
                print(f"    C:      {list(c_result[start:end])}")

# Test full encryption: Python vs. C
def test_encrypt_block():
    print("Testing aes_encrypt_block")

    rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte * 16)

    for i in range(3):
        plaintext = bytearray(random.randint(0, 255) for _ in range(16))
        key = bytearray(random.randint(0, 255) for _ in range(16))

        # Python AES
        aes = AES(key)
        py_result = aes.encrypt_block(plaintext)

        # C AES
        c_plaintext = ctypes.create_string_buffer(bytes(plaintext), 16)
        c_key = ctypes.create_string_buffer(bytes(key), 16)
        c_result_ptr = rijndael.aes_encrypt_block(c_plaintext, c_key)
        c_result = bytearray(c_result_ptr.contents)

        # Compare
        if py_result == c_result:
            print(f"  Test {i+1}: PASSED")
        else:
            print(f"  Test {i+1}: FAILED")
            print(f"  Plaintext: {list(plaintext)}")
            print(f"  Key: {list(key)}")
            print(f"  Python result: {list(py_result)}")
            print(f"  C result: {list(c_result)}")

# Test full decryption: Python vs. C
def test_decrypt_block():
    print("Testing aes_decrypt_block")

    rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte * 16)

    for i in range(3):
        plaintext = bytearray(random.randint(0, 255) for _ in range(16))
        key = bytearray(random.randint(0, 255) for _ in range(16))

        aes = AES(key)
        ciphertext = aes.encrypt_block(plaintext)

        # C decryption
        c_ciphertext = ctypes.create_string_buffer(bytes(ciphertext), 16)
        c_key = ctypes.create_string_buffer(bytes(key), 16)
        c_result_ptr = rijndael.aes_decrypt_block(c_ciphertext, c_key)
        c_result = bytearray(c_result_ptr.contents)

        # Compare to original plaintext
        if plaintext == c_result:
            print(f"  Test {i+1}: PASSED")
        else:
            print(f"  Test {i+1}: FAILED")
            print(f"  Original plaintext: {list(plaintext)}")
            print(f"  Key: {list(key)}")
            print(f"  Ciphertext: {list(ciphertext)}")
            print(f"  Decrypted (C): {list(c_result)}")

def main():
    # Basic AES transformations
    test_function("sub_bytes", rijndael.sub_bytes, py_sub_bytes)
    test_function("inv_sub_bytes", rijndael.inv_sub_bytes, py_inv_sub_bytes)
    test_shift_rows_function("shift_rows", rijndael.shift_rows, py_shift_rows)
    test_shift_rows_function("inv_shift_rows", rijndael.inv_shift_rows, py_inv_shift_rows)
    test_function("mix_columns", rijndael.mix_columns, py_mix_columns)
    test_function("inv_mix_columns", rijndael.inv_mix_columns, py_inv_mix_columns)
    test_function("add_round_key", rijndael.add_round_key, py_add_round_key)

    # Key expansion
    test_key_expansion()

    # Full AES block operations
    test_encrypt_block()
    test_decrypt_block()

if __name__ == "__main__":
    main()