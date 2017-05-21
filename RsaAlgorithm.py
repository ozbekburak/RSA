import math,string
import EuclideanAlgorithm as ea

# it is just a simple example, you can generate your keys by yourself.
p = 5
q = 11
modulus_n = p*q
totient = (p-1)*(q-1)

e = 7 # public key e // e < totient and coprime with totient
d = ea.Gcd(totient,e) # d -> decrypt key, private # i use my xgcd algorithm,you can use yours.
if (d<0):
    d += totient

def encryptionFunction(makeCiphertext):
    print("ENCRYPTION STARTING... -->")
    enc_plain_list = []
    for i in range (0,makeCiphertext.__len__(),1):
        encrypted_plaintext = int((makeCiphertext[i]**e) % (modulus_n))
        enc_plain_list.append(encrypted_plaintext)
    print ("Encrypted text: ", enc_plain_list)
    return enc_plain_list

def decryptionFunction(decryptCipher):
    print("DECRYPTION STARTING.. -->")
    dec_plain = []
    for i in range (0,decryptCipher.__len__(),1):
        decrypted_plaintext = (int(decryptCipher[i]**d) % (modulus_n))
        dec_plain.append(string.ascii_lowercase[decrypted_plaintext-1])
    print ("Decrypted text: ", dec_plain)

def main():
    print("-----'R'ivest,'S'hamir,'A'dleman-------")
    plaintext = input("Enter plaintext: ")
    plaintext = plaintext.lower()
    output = []
    for character in plaintext:
        number = ord(character) - 96
        output.append(number)
    decryptCipher = encryptionFunction(output)
    decryptionFunction(decryptCipher)

main()
input("press Enter to exit.")

#'n' and 'e' for encryption
#'d' and totient for decryption
