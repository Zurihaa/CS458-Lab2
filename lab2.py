#pip install cryptodome
import Crypto
print(Crypto.__version__)


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
            while True:
                try:
                    key = dict(input("Enter your key: "))
                    if key == None:
                        key = permutation_alphabet()
                    break
                except ValueError as e:
                    print("Invalid input. Try Again.")
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
            return 1
        elif option == 7:
            return 1
        elif option == 8:
            return 1
        
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
                    if key == None:
                        key = permutation_alphabet()
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
            return 1
        elif option == 7:
            return 1
        elif option == 8:
            return 1

main()