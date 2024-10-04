import random
import string

def shiftcipher(text,n):
    ciphertext = ""
    for i in range(len(text)):
        ch = text[i]
        if ch == " ":
            ciphertext += " "
        elif ch.isupper():
            ciphertext += chr((ord(ch) + n-65) % 26 + 65)        
        else:
            ciphertext += chr((ord(ch) + n-97) % 26 + 97)
    return ciphertext

def permutation_alphabet():
    alphabet = list(range(26))
    random.shuffle(alphabet)
    lowerAlphabet = string.ascii_lowercase
    key = {}
    for i in range(26):
        key[lowerAlphabet[i]] = lowerAlphabet[alphabet[i]]
    return key

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

def simpletranspositioncipher(text, row, column):
    
    text = text.replace(" ", "x")

    total = row * column
    fill = total - len(text)

    if fill > 0:
        text += "x" * fill

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

def doubletranspositioncipher(text, row, column, row_pattern, col_pattern):
    
    text = text.replace(" ", "x")

    total = row * column
    fill = total - len(text)

    if fill > 0:
        text += "x" * fill

    matrix = []

    for i in range(row):
        matrix = matrix + [[]]
        for j in range(column):
            matrix[i] = matrix[i] + [' ']

    k = 0

    for i in range(column):
        for j in range(row):
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

#Reference from https://www.geeksforgeeks.org/vigenere-cipher
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

def vigeneredecrypht(text, key):
    text_key = (key * (len(text) // len(key))) + key[:len(text) % len(key)]

    ciphertext = ""

    for i in range(len(text)):
        ch = text[i]
        if ch.isupper():
            ciphertext += chr((ord(ch) - ord(text_key[i]) + 26) % 26 + ord("A"))
        elif ch.islower():
            ciphertext += chr((ord(ch) - ord(text_key[i]) + 26) % 26 + ord("A"))
        else:
            ciphertext += ch
    
    return ciphertext


print("Choose your encryption mode:")
print("1. Shift Cipher")
print("2. Permutation Cipher")

text = input("Plain Text: ")
#mode = input("Choose your encryption mode: ")
#row = int(input())
#col = int(input())
print(vigeneredecrypht(text, "VIG"))