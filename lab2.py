import string
import random
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64


def shiftcipher(text,key):
    ciphertext = ""
    for i in range(len(text)):
        ch = text[i]
        if ch == " ":
            ciphertext += " "
        elif ch.isupper():
            ciphertext += chr((ord(ch) + key - 65) % 26 + 65)        
        else:
            ciphertext += chr((ord(ch) + key - 97) % 26 + 97)
    return ciphertext

def shift_decryption(text, key):
    ciphertext = ""
    for i in range(len(text)):
        ch = text[i]
        if ch == " ":
            ciphertext += " "
        elif ch.isupper():
            ciphertext += chr((ord(ch) - key - 65) % 26 + 65)        
        else:
            ciphertext += chr((ord(ch) - key - 97) % 26 + 97)
    return ciphertext

def permutation_alphabet():
    alphabet = list(range(26))
    random.shuffle(alphabet)
    lowerAlphabet = string.ascii_lowercase
    key = {}
    for i in range(26):
        key[lowerAlphabet[i]] = lowerAlphabet[alphabet[i]]
    return key

def reverse_key(key):
    return {i: j for j, i in key.items()}

def permutationcipher(text, key):
    ciphertext = ""
    for i in text:
        if i == " ":
            ciphertext += " "
        else:
            uppercase = i.isupper()
            ch = i.lower()
            permuted_char = key[ch]
            ciphertext += permuted_char.upper() if uppercase else permuted_char
    return ciphertext

def permutationdecrypt(text, key):
    ciphertext = ""
    reverse = reverse_key(key)
    for i in text:
        if i == " ":
            ciphertext += " "
        else:
            uppercase = i.isupper()
            ch = i.lower()
            og_char = reverse[ch]
            ciphertext += og_char.upper() if uppercase else og_char
    return ciphertext

def simpletranspositioncipher(text, row, column):
    
    text = text.replace(" ", "X")

    total = row * column
    fill = total - len(text)

    if fill > 0:
        text += "X" * fill

    matrix = []

    for i in range(row):
        matrix = matrix + [[]]
        for j in range(column):
            matrix[i] = matrix[i] + [' ']

    k = 0

    for i in range(row):
        for j in range(column):
            matrix[i][j] = text[k]
            k += 1

    ciphertext = ""
    for i in range(column):
        for j in range(row):
            ciphertext += matrix[j][i]

    return ciphertext

def simpletranspositiondecrypt(text, row, column):
    matrix = []
    
    for i in range(row):
        matrix = matrix + [[]]
        for j in range(column):
            matrix[i] = matrix[i] + [' ']

    k = 0

    for i in range(column):
        for j in range(row):
            matrix[j][i] = text[k]
            k += 1

    ciphertext = ""

    for i in range(row):
        for j in range(column):
            ciphertext += matrix [i][j]

    return ciphertext

def doubletranspositioncipher(text, row, column, row_pattern:list, col_pattern:list):
    
    text = text.replace(" ", "x")

    total = row * column
    fill = total - len(text)

    if fill > 0:
        text += "X" * fill

    matrix = []

    for i in range(row):
        matrix = matrix + [[]]
        for j in range(column):
            matrix[i] = matrix[i] + [' ']

    k = 0

    for i in range(row):
        for j in range(column):
            matrix[i][j] = text[k]
            k += 1

    col_matrix = [matrix[i-1] for i in row_pattern]
    
    encrypt_matrix = []

    for i in range(row):
        encrypt_matrix = encrypt_matrix + [[]]
        for j in range(column):
            encrypt_matrix[i] = encrypt_matrix[i] + [' ']

    for i in range(row):
        k = 0
        for j in col_pattern:
            encrypt_matrix[i][k] = col_matrix[i][j-1]
            k += 1

    ciphertext = ""
    for i in range(row):
        for j in range(column):
            ciphertext += encrypt_matrix[i][j]

    return ciphertext

def doubletranspositiondecrypt(text, row, column, row_pattern:list, col_pattern:list):
    decrypt_matrix = []

    for i in range(row):
        decrypt_matrix = decrypt_matrix + [[]]
        for j in range(column):
            decrypt_matrix[i] = decrypt_matrix[i] + [' ']

    k = 0
    for i in range(row):
        for j in range(column):
            decrypt_matrix[i][j] = text[k]
            k += 1

    og_matrix = []
    for i in range(row):
        og_matrix = og_matrix + [[]]
        for j in range(column):
            og_matrix[i] = og_matrix[i] + [' ']
    
    for i in range(row):
        for j, col_pos in enumerate(col_pattern):
            og_matrix[i][col_pos - 1] = decrypt_matrix[i][j]

    final_matrix = []
    for i, row_pos in enumerate(row_pattern):
        final_matrix.append(og_matrix[row_pos - 1])

    ciphertext = ""
    for i in range(row):
        for j in range(column):
            ciphertext += final_matrix[i][j]

    return ciphertext

#Reference from https://www.geeksforgeeks.org/vigenere-cipher/
def vigenerecipher(text, key):

    text_key = (key * (len(text) // len(key))) + key[:len(text) % len(key)]

    ciphertext = ""

    for i in range(len(text)):
        ch = text[i]
        if ch.isupper():
            ciphertext += chr((ord(ch) + ord(text_key[i]) - 2 * ord("A")) % 26 + ord("A"))
        elif ch.islower():
            ciphertext += chr((ord(ch) + ord(text_key[i]) - 2 * ord("A")) % 26 + ord("A"))
        else:
            ciphertext += ch
    
    return ciphertext

def vigeneredecrypt(text, key):
    text_key = (key * (len(text) // len(key))) + key[:len(text) % len(key)]

    decrypttext = ""

    for i in range(len(text)):
        ch = text[i]
        if ch.isupper():
            decrypttext += chr((ord(ch) - ord(text_key[i]) + 26) % 26 + ord("A"))
        elif ch.islower():
            decrypttext += chr((ord(ch) - ord(text_key[i]) + 26) % 26 + ord("A"))
        else:
            decrypttext += ch
    
    return decrypttext

#Reference from https://stackoverflow.com/questions/59925060/des-encryption-in-python
def aes_encrypt(text, key, mode):
    if mode == "ECB":
        aes = AES.new(key, AES.MODE_ECB)
        padded_text = pad(text.encode(), AES.block_size)
        encrypted_text = aes.encrypt(padded_text)
    elif mode == "CBC":
        iv = get_random_bytes(16)
        aes = AES.new(key, AES.MODE_CBC, iv)
        padded_text = pad(text.encode(), AES.block_size)
        encrypted_text = aes.encrypt(padded_text)
    elif mode == "CFB":
        iv = get_random_bytes(16)
        aes = AES.new(key, AES.MODE_CFB, iv)
        padded_text = pad(text.encode(), AES.block_size)
        encrypted_text = aes.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode()

def aes_decrypt(encrypted_text, key, mode):
    encrypted_text = base64.b64decode(encrypted_text)

    if mode == "ECB":
        aes = AES.new(key, AES.MODE_ECB)
        decrypted_padded_text = aes.decrypt(encrypted_text)
        return unpad(decrypted_padded_text, AES.block_size).decode()

    elif mode == "CBC":
        if len(encrypted_text) < 16:
            raise ValueError("Invalid encrypted data")
        iv = encrypted_text[:16]
        aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_text = aes.decrypt(encrypted_text[16:])
        return unpad(decrypted_padded_text, AES.block_size).decode()

    elif mode == "CFB":
        if len(encrypted_text) < 16:
            raise ValueError("Invalid encrypted data")
        iv = encrypted_text[:16]
        decrypted_text = aes.decrypt(encrypted_text[16:])
        return decrypted_text.decode()

def des_encrypt(text, key, mode):
    if mode == "ECB":
        des = DES.new(key, DES.MODE_ECB)
        padded_text = pad(text.encode(), DES.block_size)
        encrypted_text = des.encrypt(padded_text)
    elif mode == "CBC":
        iv = get_random_bytes(8)
        des = DES.new(key, DES.MODE_CBC, iv)
        padded_text = pad(text.encode(), DES.block_size)
        encrypted_text = des.encrypt(padded_text)
    elif mode == "CFB":
        iv = get_random_bytes(8)
        des = DES.new(key, DES.MODE_CFB, iv)
        padded_text = pad(text.encode(), DES.block_size)
        encrypted_text = des.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode()

def des_decrypt(text, key, mode):
    encrypted = base64.b64decode(text)
    
    if mode == "ECB":
        des = DES.new(key, DES.MODE_ECB)
        decrypted_data = des.decrypt(encrypted)
        plaintext = unpad(decrypted_data, DES.block_size)
        plaintext = decrypted_data
    elif mode == "CBC":
        iv = key
        des = DES.new(key, DES.MODE_CBC, iv)
        decrypted_data = des.decrypt(encrypted)
        plaintext = unpad(decrypted_data, DES.block_size)
        plaintext = decrypted_data
    elif mode == "CFB":
        iv = key 
        des = DES.new(key, DES.MODE_CFB, iv)
        plaintext = des.decrypt(encrypted)    
    return plaintext.decode(errors="ignore")

def des3_encrypt(text, key, mode):
    if mode == "ECB":
        des3 = DES3.new(key, DES3.MODE_ECB)
        padded_text = pad(text.encode(), DES3.block_size)
        encrypted_text = des3.encrypt(padded_text)
    elif mode == "CBC":
        iv = get_random_bytes(8)
        des3 = DES3.new(key, DES3.MODE_CBC, iv)
        padded_text = pad(text.encode(), DES3.block_size)
        encrypted_text = des3.encrypt(padded_text)
    elif mode == "CFB":
        iv = get_random_bytes(8)
        des3 = DES.new(key, DES3.MODE_CFB, iv)
        padded_text = pad(text.encode(), DES3.block_size)
        encrypted_text = des3.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode()

def des3_decrypt(text, key, mode):
    encrypted = base64.b64decode(text)
    
    if mode == "ECB":
        des3 = DES3.new(key, DES3.MODE_ECB)
        decrypted_data = des3.decrypt(encrypted)
        plaintext = unpad(decrypted_data, DES3.block_size)
        plaintext = decrypted_data
    elif mode == "CBC":
        iv = key
        des3 = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted_data = des3.decrypt(encrypted)
        plaintext = unpad(decrypted_data, DES3.block_size)
        plaintext = decrypted_data
    elif mode == "CFB":
        iv = key 
        des3 = DES3.new(key, DES3.MODE_CFB, iv)
        plaintext = des3.decrypt(encrypted)    
    return plaintext.decode(errors="ignore")

def main():
    while True:
        try:
            choice = int(input("Do you want to encrypt or decrypt (1 for encrypt/2 for decrypt) ?"))
            if choice not in [1, 2]:
                raise ValueError("Choice must be 1 or 2.")
            break
        except ValueError as e:
            print("Invalid input. Please enter 1 or 2.")
  
    while True:
        try:
            plaintext = input("Enter plaintext: ")
            if plaintext == "": 
                raise ValueError("Plaintext cannot be empty.")
            break
        except ValueError as e:
            print("Invalid input. Please enter an text for plaintext.")
  
    if choice == 1:
        print("Choose your encryption mode:")
        print("1. Shift")
        print("2. Permutation")
        print("3. Simple Transposition")
        print("4. Double Transposition")
        print("5. Vigenere")
        print("6. AES")
        print("7. DES")
        print("8. 3DES")

        while True:
            try:
                option = int(input("Enter from 1 to 8: "))
                if choice not in [1, 2, 3, 4, 5, 6, 7, 8]:
                    raise ValueError("Choice must be from 1 to 8.")
                break
            except ValueError as e:
                print("Invalid input. Choice must be from 1 to 8.")

        if option == 1:
            while True:
                try:
                    n = int(input("Enter key: "))
                    if n == 0 or n >26: 
                        raise ValueError("Key cannot be 0.")
                    break
                except ValueError as e:
                    print("Invalid input. Please enter an int for key.")
            print("Ciphertext: ", shiftcipher(plaintext, n))
        elif option == 2:
            key = permutation_alphabet()

            print("This is your keys:", key)
            print("Ciphertext: ", permutationcipher(plaintext, key))
        elif option == 3:
            while True:
                try:
                    row = int(input("Enter number of rows: "))
                    if row is not int:
                        raise ValueError("Must be an interger")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            while True:
                try:
                    column = int(input("Enter number of rows: "))
                    if column is not int:
                        raise ValueError("Must be an interger")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            print("CipherText: ", simpletranspositioncipher(plaintext, row, column))
        elif option == 4:
            while True:
                try:
                    row = int(input("Enter number of rows: "))
                    if row is not int:
                        raise ValueError("Must be an interger")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            while True:
                try:
                    column = int(input("Enter number of rows: "))
                    if column is not int:
                        raise ValueError("Must be an interger")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            while True:
                try:
                    row_pattern = list[int](input("Enter row pattern: "))
                    if row_pattern is not list[int] or len(row_pattern) != row:
                        raise ValueError("Try Again")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            while True:
                try:
                    col_pattern = list[int](input("Enter col pattern: "))
                    if col_pattern is not list[int] or len(col_pattern) != row:
                        raise ValueError("Try Again")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            print("CipherText: ", doubletranspositioncipher(plaintext, row, column, row_pattern, col_pattern))
        elif option == 5:
            while True:
                try:
                    key = str(input("Enter your key: "))
                    if row is not int:
                        raise ValueError("Try Again")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            print(vigenerecipher(plaintext, key))
        elif option == 6:
            while True:
                try:
                    mode = str(input("Enter your mode (ECB, CBC or CFB): "))
                    if mode not in ["ECB", "CBC", "CFB"]:
                        raise ValueError("Try Again")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            
            key = input("Enter a 16, 24 or 32-byte key: ").encode()

            while True:
                try:
                    if not isinstance(key, bytes):
                        raise ValueError("Key must be of type 'bytes'")
                    if len(key) not in {16, 24, 32}:
                        raise ValueError("Key must be 16, 24 or 32 bytes long")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            
            print("Encrypted text: ", aes_encrypt(text, key, mode))
        elif option == 7:
            while True:
                try:
                    mode = str(input("Enter your mode (ECB, CBC or CFB): "))
                    if mode not in ["ECB", "CBC", "CFB"]:
                        raise ValueError("Try Again")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            
            key = input("Enter a 8-byte key: ").encode()

            while True:
                try:
                    if not isinstance(key, bytes):
                        raise ValueError("Key must be of type 'bytes'")
                    if len(key) not in {8}:
                        raise ValueError("Key must be 8 bytes long")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            
            print("Encrypted text: ", des_encrypt(text, key, mode))
        elif option == 8:
            while True:
                try:
                    mode = str(input("Enter your mode (ECB, CBC or CFB): "))
                    if mode not in ["ECB", "CBC", "CFB"]:
                        raise ValueError("Try Again")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            
            key = input("Enter a 16 or 24-byte key: ").encode()

            while True:
                try:
                    if not isinstance(key, bytes):
                        raise ValueError("Key must be of type 'bytes'")
                    if len(key) not in {16, 24}:
                        raise ValueError("Key must be 16 or 24 bytes long")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            
            print("Encrypted text: ", des3_encrypt(text, key, mode))
        
    elif choice == 2:
        print("Choose your decryption mode:")
        print("1. Shift")
        print("2. Permutation")
        print("3. Simple Transposition")
        print("4. Double Transposition")
        print("5. Vigenere")
        print("6. AES")
        print("7. DES")
        print("8. 3DES")

        while True:
            try:
                option = int(input("Enter from 1 to 8: "))
                if choice not in [1, 2, 3, 4, 5, 6, 7, 8]:
                    raise ValueError("Choice must be from 1 to 8.")
                break
            except ValueError as e:
                print("Invalid input. Choice must be from 1 to 8.")

        if option == 1:
            while True:
                try:
                    n = int(input("Enter key: "))
                    if n == 0 or n >26: 
                        raise ValueError("Key cannot be 0.")
                    break
                except ValueError as e:
                    print("Invalid input. Please enter an int for key.")
            print("Ciphertext: ", shift_decryption(plaintext, n))
        elif option == 2:
            while True:
                try:
                    key = dict(input("Enter your key: "))
                    if key is not dict:
                        raise ValueError("Please enter the key")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            print("Ciphertext: ", permutationdecrypt(plaintext, key))
        elif option == 3:
            while True:
                try:
                    row = int(input("Enter number of rows: "))
                    if row is not int:
                        raise ValueError("Must be an interger")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            while True:
                try:
                    column = int(input("Enter number of rows: "))
                    if column is not int:
                        raise ValueError("Must be an interger")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            print("CipherText: ", simpletranspositiondecrypt(plaintext, row, column))
        elif option == 4:
            while True:
                try:
                    row = int(input("Enter number of rows: "))
                    if row is not int:
                        raise ValueError("Must be an interger")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            while True:
                try:
                    column = int(input("Enter number of rows: "))
                    if column is not int:
                        raise ValueError("Must be an interger")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            while True:
                try:
                    row_pattern = list[int](input("Enter row pattern: "))
                    if row_pattern is not list[int] or len(row_pattern) != row:
                        raise ValueError("Try Again")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            while True:
                try:
                    col_pattern = list[int](input("Enter col pattern: "))
                    if col_pattern is not list[int] or len(col_pattern) != row:
                        raise ValueError("Try Again")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            print("CipherText: ", doubletranspositiondecrypt(plaintext, row, column, row_pattern, col_pattern))
        elif option == 5:
            while True:
                try:
                    key = str(input("Enter your key: "))
                    if row is not int:
                        raise ValueError("Try Again")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            print(vigeneredecrypt(plaintext, key))
        elif option == 6:
            while True:
                try:
                    mode = str(input("Enter your mode (ECB, CBC or CFB): "))
                    if mode not in ["ECB", "CBC", "CFB"]:
                        raise ValueError("Try Again")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            
            key = input("Enter a 16 or 24-byte key: ").encode()

            while True:
                try:
                    if not isinstance(key, bytes):
                        raise ValueError("Key must be of type 'bytes'")
                    if len(key) not in {16, 24, 32}:
                        raise ValueError("Key must be 16, 24 or 32 bytes long")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            
            print("Decrypted text: ", aes_decrypt(text, key, mode))
        elif option == 7:
            while True:
                try:
                    mode = str(input("Enter your mode (ECB, CBC or CFB): "))
                    if mode not in ["ECB", "CBC", "CFB"]:
                        raise ValueError("Try Again")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            
            key = input("Enter a 8-byte key: ").encode()

            while True:
                try:
                    if not isinstance(key, bytes):
                        raise ValueError("Key must be of type 'bytes'")
                    if len(key) not in {8}:
                        raise ValueError("Key must be 8 bytes long")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            
            print("Decrypted text: ", des_decrypt(text, key, mode))
        elif option == 8:
            while True:
                try:
                    mode = str(input("Enter your mode (ECB, CBC or CFB): "))
                    if mode not in ["ECB", "CBC", "CFB"]:
                        raise ValueError("Try Again")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            
            key = input("Enter a 16 or 24-byte key: ").encode()

            while True:
                try:
                    if not isinstance(key, bytes):
                        raise ValueError("Key must be of type 'bytes'")
                    if len(key) not in {16, 24}:
                        raise ValueError("Key must be 16 or 24 bytes long")
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
            
            print("Decrypted text: ", des3_decrypt(text, key, mode))

if __name__ == "__main__":
    main()