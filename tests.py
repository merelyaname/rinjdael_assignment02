import ctypes
import os
import sys
# Add the path to the Python AES implementation
sys.path.append(os.path.join(os.path.dirname(__file__), "python_aes"))
import random

# Import the Python AES functions for comparison
from python_aes.aes import sub_bytes as py_sub_bytes, inv_sub_bytes as py_inv_sub_bytes
from python_aes.aes import shift_rows as py_shift_rows, inv_shift_rows as py_inv_shift_rows
from python_aes.aes import mix_columns as py_mix_columns, inv_mix_columns as py_inv_mix_columns
from python_aes.aes import add_round_key as py_add_round_key
from python_aes.aes import AES, bytes2matrix, matrix2bytes

# Load the C library
rijndael = ctypes.CDLL('./rijndael.dll')

# Utility functions to convert between formats
def transpose_matrix(matrix):
    """Transpose a 4x4 matrix"""
    return [[matrix[j][i] for j in range(4)] for i in range(4)]

def transpose_bytes(data):
    """Transpose a 16-byte array by converting to matrix, transposing, and converting back"""
    matrix = bytes2matrix(data)
    transposed = transpose_matrix(matrix)
    return matrix2bytes(transposed)

# Function to expand key in Python
def py_expand_key(key_bytes):
    aes = AES(key_bytes)
    expanded = []
    for matrix in aes._key_matrices:
        for row in matrix:
            for byte in row:
                expanded.append(byte)
    return bytes(expanded)

# Test shift_rows and inv_shift_rows with transposition
def test_shift_function(func_name, c_func, py_func):
    print(f"Testing {func_name}")
    
    for i in range(3):
        # Generate random input
        input_data = bytes(random.randint(0, 255) for _ in range(16))
        
        # Run Python function on the original data
        py_matrix = bytes2matrix(input_data)
        py_func(py_matrix)
        py_result = matrix2bytes(py_matrix)
        
        # For C, we need to transpose the data
        # Since your C implementation expects column-major format
        c_data = transpose_bytes(input_data)
        c_buffer = ctypes.create_string_buffer(c_data, 16)
        
        # Run C function
        c_func(c_buffer)
        
        # Transpose back to compare
        c_result = transpose_bytes(c_buffer.raw)
        
        # Compare results
        if py_result == c_result:
            print(f"  Test {i+1}: PASSED")
        else:
            print(f"  Test {i+1}: FAILED")
            print(f"  Python result: {list(py_result)}")
            print(f"  C result: {list(c_result)}")

# Test a standard function
def test_function(func_name, c_func, py_func):
    print(f"Testing {func_name}")
    
    for i in range(3):
        # Generate random input
        input_data = bytes(random.randint(0, 255) for _ in range(16))
        
        # For add_round_key, we need a second input
        if func_name == "add_round_key":
            key_data = bytes(random.randint(0, 255) for _ in range(16))
            key_matrix = bytes2matrix(key_data)
        
        # Run Python function
        py_matrix = bytes2matrix(input_data)
        if func_name == "add_round_key":
            py_func(py_matrix, key_matrix)
        else:
            py_func(py_matrix)
        py_result = matrix2bytes(py_matrix)
        
        # Run C function
        c_buffer = ctypes.create_string_buffer(input_data, 16)
        if func_name == "add_round_key":
            c_key = ctypes.create_string_buffer(key_data, 16)
            c_func(c_buffer, c_key)
        else:
            c_func(c_buffer)
        c_result = bytes(c_buffer.raw)
        
        # Compare results
        if py_result == c_result:
            print(f"  Test {i+1}: PASSED")
        else:
            print(f"  Test {i+1}: FAILED")
            print(f"  Python result: {list(py_result)}")
            print(f"  C result: {list(c_result)}")

# Test the key expansion
def test_key_expansion():
    print("Testing expand_key")
    
    rijndael.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte * 176)
    
    for i in range(3):
        # Generate random key
        key = bytes(random.randint(0, 255) for _ in range(16))
        
        # Run Python key expansion
        py_result = py_expand_key(key)
        
        # Run C key expansion
        c_key = ctypes.create_string_buffer(key, 16)
        c_result_ptr = rijndael.expand_key(c_key)
        c_result = bytes(c_result_ptr.contents)
        
        # Compare results
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

# Test encryption
def test_encrypt_block():
    print("Testing aes_encrypt_block")
    
    rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte * 16)
    
    for i in range(3):
        # Generate random plaintext and key
        plaintext = bytes(random.randint(0, 255) for _ in range(16))
        key = bytes(random.randint(0, 255) for _ in range(16))
        
        # Run Python encryption
        aes = AES(key)
        py_result = aes.encrypt_block(plaintext)
        
        # Transpose data for C implementation
        transposed_plaintext = transpose_bytes(plaintext)
        
        # Run C encryption
        c_plaintext = ctypes.create_string_buffer(transposed_plaintext, 16)
        c_key = ctypes.create_string_buffer(key, 16)
        c_result_ptr = rijndael.aes_encrypt_block(c_plaintext, c_key)
        
        # Transpose C result back for comparison
        c_result_raw = bytes(c_result_ptr.contents)
        c_result = transpose_bytes(c_result_raw)
        
        # Compare results
        if py_result == c_result:
            print(f"  Test {i+1}: PASSED")
        else:
            print(f"  Test {i+1}: FAILED")
            print(f"  Plaintext: {list(plaintext)}")
            print(f"  Key: {list(key)}")
            print(f"  Python result: {list(py_result)}")
            print(f"  C result: {list(c_result)}")

# Test decryption
def test_decrypt_block():
    print("Testing aes_decrypt_block")
    
    rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte * 16)
    
    for i in range(3):
        # Generate random plaintext and key
        plaintext = bytes(random.randint(0, 255) for _ in range(16))
        key = bytes(random.randint(0, 255) for _ in range(16))
        
        # Encrypt with Python
        aes = AES(key)
        ciphertext = aes.encrypt_block(plaintext)
        
        # Transpose ciphertext for C implementation
        transposed_ciphertext = transpose_bytes(ciphertext)
        
        # Decrypt with C
        c_ciphertext = ctypes.create_string_buffer(transposed_ciphertext, 16)
        c_key = ctypes.create_string_buffer(key, 16)
        c_result_ptr = rijndael.aes_decrypt_block(c_ciphertext, c_key)
        
        # Transpose result back for comparison
        c_result_raw = bytes(c_result_ptr.contents)
        c_result = transpose_bytes(c_result_raw)
        
        # Compare results
        if plaintext == c_result:
            print(f"  Test {i+1}: PASSED")
        else:
            print(f"  Test {i+1}: FAILED")
            print(f"  Original plaintext: {list(plaintext)}")
            print(f"  Key: {list(key)}")
            print(f"  Ciphertext: {list(ciphertext)}")
            print(f"  Decrypted (C): {list(c_result)}")

def main():
    # Test individual transformation functions
    test_function("sub_bytes", rijndael.sub_bytes, py_sub_bytes)
    test_function("inv_sub_bytes", rijndael.inv_sub_bytes, py_inv_sub_bytes)
    
    # Test shift rows functions with special handling for transposition
    test_shift_function("shift_rows", rijndael.shift_rows, py_shift_rows)
    test_shift_function("inv_shift_rows", rijndael.inv_shift_rows, py_inv_shift_rows)
    
    test_function("mix_columns", rijndael.mix_columns, py_mix_columns)
    test_function("inv_mix_columns", rijndael.inv_mix_columns, py_inv_mix_columns)
    test_function("add_round_key", rijndael.add_round_key, py_add_round_key)
    
    # Test key expansion
    test_key_expansion()
    
    # Test encryption and decryption
    test_encrypt_block()
    test_decrypt_block()

if __name__ == "__main__":
    main()