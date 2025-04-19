import ctypes
import os
import sys
import random

# Add the path to the Python AES implementation
sys.path.append(os.path.join(os.path.dirname(__file__), "python-aes"))

# Import the Python AES functions for comparison
from aes import sub_bytes as py_sub_bytes, inv_sub_bytes as py_inv_sub_bytes
from aes import shift_rows as py_shift_rows, inv_shift_rows as py_inv_shift_rows
from aes import mix_columns as py_mix_columns, inv_mix_columns as py_inv_mix_columns
from aes import add_round_key as py_add_round_key
from aes import AES

# Load the C library
rijndael = ctypes.CDLL('./rijndael.so')

# Utility functions to convert between formats
def to_matrix_row_major(flat_array):
    return [list(flat_array[i*4:(i+1)*4]) for i in range(4)]

def from_matrix_row_major(matrix):
    return bytearray(b for row in matrix for b in row)

def to_matrix_column_major(flat_array):
    return [[flat_array[r + 4 * c] for c in range(4)] for r in range(4)]

def from_matrix_column_major(matrix):
    return bytearray(matrix[r][c] for c in range(4) for r in range(4))

# Function to expand key in Python
def py_expand_key(key_bytes):
    aes = AES(key_bytes)
    expanded = []
    for matrix in aes._key_matrices:
        for row in matrix:
            for byte in row:
                expanded.append(byte)
    return bytes(expanded)

# Test a specific function
def test_function(func_name, c_func, py_func, conversions=True):
    print(f"Testing {func_name}")
    
    # Test with 3 different random inputs
    for i in range(3):
        # Generate random input
        input_data = bytearray(random.randint(0, 255) for _ in range(16))
        
        # For add_round_key, we need a second input
        if func_name == "add_round_key":
            key_data = bytearray(random.randint(0, 255) for _ in range(16))
            key_matrix = to_matrix_row_major(key_data)
        
        # Copy the input for Python
        py_input = to_matrix_row_major(input_data) if conversions else bytes(input_data)
        
        # Run Python function
        if func_name == "add_round_key":
            py_func(py_input, key_matrix)
        else:
            py_func(py_input)
        
        # Convert Python result back to flat array
        py_result = from_matrix_row_major(py_input) if conversions else py_input
        
        # Prepare C input
        c_input = ctypes.create_string_buffer(bytes(input_data), 16)
        
        # Run C function
        if func_name == "add_round_key":
            c_key = ctypes.create_string_buffer(bytes(key_data), 16)
            c_func(c_input, c_key)
        else:
            c_func(c_input)
        
        # Convert C result to Python bytes
        c_result = bytearray(c_input.raw)
        
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
        key = bytearray(random.randint(0, 255) for _ in range(16))
        
        # Run Python key expansion
        py_result = py_expand_key(key)
        
        # Run C key expansion
        c_key = ctypes.create_string_buffer(bytes(key), 16)
        c_result_ptr = rijndael.expand_key(c_key)
        c_result = bytearray(c_result_ptr.contents)
        
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
        plaintext = bytearray(random.randint(0, 255) for _ in range(16))
        key = bytearray(random.randint(0, 255) for _ in range(16))
        
        # Run Python encryption
        aes = AES(key)
        py_result = aes.encrypt_block(plaintext)
        
        # Run C encryption
        c_plaintext = ctypes.create_string_buffer(bytes(plaintext), 16)
        c_key = ctypes.create_string_buffer(bytes(key), 16)
        c_result_ptr = rijndael.aes_encrypt_block(c_plaintext, c_key)
        c_result = bytearray(c_result_ptr.contents)
        
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
        plaintext = bytearray(random.randint(0, 255) for _ in range(16))
        key = bytearray(random.randint(0, 255) for _ in range(16))
        
        # Encrypt with Python
        aes = AES(key)
        ciphertext = aes.encrypt_block(plaintext)
        
        # Decrypt with C
        c_ciphertext = ctypes.create_string_buffer(bytes(ciphertext), 16)
        c_key = ctypes.create_string_buffer(bytes(key), 16)
        c_result_ptr = rijndael.aes_decrypt_block(c_ciphertext, c_key)
        c_result = bytearray(c_result_ptr.contents)
        
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
    test_function("shift_rows", rijndael.shift_rows, py_shift_rows)
    test_function("inv_shift_rows", rijndael.inv_shift_rows, py_inv_shift_rows)
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