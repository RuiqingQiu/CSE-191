# implement EME encryption algorithm
# T is tweakble parameter, K is the key and P is the plaintext
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import strxor
import base64
import os

# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 16  # 128 bits

def EME_E(T,K,P):
    # create a AES block cipher with key L
    # default AES mode is ECB
    # default n  = 128 bits, 16 bytes, P = m * 128 length
    n = 16
    m  = len(P)/16   # how many blocks do we have
    print "m is ", m

    # create a AES block cipher, use ECB mode
    cipher = AES.new(K,AES.MODE_ECB)
    # Initial vector
    IV = ''
    for i in range(0,n):
        IV = IV + '0'
    print "IV is ", IV
    print "IV length is ", len(IV)

    # TO DO : L needs to time 2 later !
    L =  cipher.encrypt(IV)
    a = len(L)
    print "1 ", a
    L = shift_left(L, 1)
    b = len(L)
    print "2 ", b

    if a != b:
        print "length mismatch"

    print "L is ", L

    count = 0
    PPP_list = [] # store all the PPP obtained
    for i in range(1,m+1):
        P_i = P[count * n :i*n]
        count = count + 1
        # TO DO version : PP = strxor_c(P_i, pow(2,i-1) * L)
        print "P_i is ", P_i
        PP = strxor.strxor(P_i,shift_left(L,i-1))
        PPP = cipher.encrypt(PP)
        PPP_list.append(PPP)

    SP = " " * 16 # empty string
    print "length of PPP_list items ",len(PPP_list[0])
    print "legnth os PPP_list is ",len(PPP_list)
    for i in range(1,len(PPP_list)):
        SP = strxor.strxor(SP,PPP_list[i])

    MP = strxor.strxor(PPP_list[0],SP)
    MP = strxor.strxor(MP,T)

    MC = cipher.encrypt(MP)
    M = strxor.strxor(MP,MC)

    CCC_list = [" "]* m
    for i in range(1,len(PPP_list)):
        #CCC_list[i] = strxor.strxor(PPP_list[i],pow(2,i-1)*M)
        CCC_list[i] = strxor.strxor(PPP_list[i], shift_left(M, i))

    SC = " " * 16
    for i in range(1,len(CCC_list)):
        SC = strxor.strxor(SC,CCC_list[i])
    CCC_list[0] = strxor.strxor(MC,SC)
    CCC_list[0] = strxor.strxor(CCC_list[0],T)

    C_list = []
    for i in range(0,len(CCC_list)):
        CC = cipher.encrypt(CCC_list[i])
        #C = strxor(CC,pow(2, i) * L)
        C = strxor.strxor(CC, shift_left(L,i))
        C_list.append(C)


    ciphertext = ""
    for i in range (0,len(C_list)):
        ciphertext = ciphertext + C_list[i]

    return ciphertext

# decryption of EME, C is the ciphertext
def EME_D(T,K,C):
     # create a AES block cipher with key L
    # default AES mode is ECB
    # default n  = 128 bits, 16 bytes, P = m * 128 length
    n = 16
    m  = len(C)/16   # how many blocks do we have
    print "m is ", m

    # create a AES block cipher, use ECB mode
    cipher = AES.new(K,AES.MODE_ECB)

    IV = ''
    for i in range(0,n):
        IV = IV + '0'
    print "IV is ", IV
    print "IV length is ", len(IV)

    # TO DO : L needs to time 2 later !
    L =  cipher.encrypt(IV)
    L = shift_left(L, 1)
    print "L is ", L

    count = 0
    CCC_list = [] # store all the PPP obtained
    for i in range(1,m+1):
        C_i = C[count * n :i*n]
        count = count + 1
        # TO DO version : PP = strxor_c(P_i, pow(2,i-1) * L)
        print "C_i is ", C_i
        CC = strxor.strxor(C_i,shift_left(L,i-1))
        CCC = cipher.decrypt(CC)
        CCC_list.append(CCC)

    SC = " " * 16
    for i in range(1,len(CCC_list)):
        SC = strxor.strxor(SC,CCC_list[i])


    MC = strxor.strxor(CCC_list[0],SC)
    MC = strxor.strxor(MC,T)

    MP = cipher.decrypt(MC)

    M = strxor.strxor(MP,MC)

    PPP_list = [" "] * m # store all the PPP obtained
    for i in range(1,len(CCC_list)):
        PPP = strxor.strxor(CCC_list[i],shift_left(M,i))
        PPP_list[i] = PPP

    SP = " " * n
    for i in range(1,len(PPP_list)):
        SP = strxor.strxor(PPP_list[i],SP)
    PPP_list[0] = strxor.strxor(MP,SP)
    PPP_list[0] = strxor.strxor(PPP_list[0],T)

    P_list = []
    for i in range (0,len(PPP_list)):
        PP = cipher.decrypt(PPP_list[i])
        P = strxor.strxor(PP,shift_left(L,i))
        P_list.append(P)

    plaintext = " "
    for i in range(0,len(P_list)):
        plaintext = plaintext + P_list[i]

    return plaintext


# Encryption
encryption_suite = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
# message length must a multiple of 16 bytes, defined block size in AES
# cipher_text is str type
# cipher_text = encryption_suite.encrypt("A really secret message. Not for prying eyes.   ")

# randomly initiate T
T = os.urandom(16)
K = os.urandom(16)
P = os.urandom(32)

def shift_left(input_string,num_of_bits):
    # convert input string to binary string
    binary_str = ''.join('{0:08b}'.format(ord(x), 'b') for x in input_string)
    # print int(binary_str,2)
    # print int(binary_str,2) << num_of_bits
    # shift and convert back to unicode string
    # print int(binary_str, 2) << num_of_bits
    a = len(binary_str)
    # print "shift left by ", num_of_bits
    # print binary_str
    # print len(binary_str)
    binary_str = "{0:b}".format(int(binary_str, 2) << num_of_bits)
    # print binary_str
    b = len(binary_str)
    # print len(binary_str)
    # shift out bits, python doesn't handle this
    if a < b:
        binary_str = binary_str[num_of_bits:]
    # if old string is longer than the current one, 0s are ignored by python
    elif a > b:
        while(len(binary_str) % 8 != 0):
            binary_str = '0' + binary_str
    
    # convert back to unicode string
    bytes_lst = []
    i = 0
    while i < len(binary_str):
        # print binary_str[i:i+8]
        bytes_lst.append(int(binary_str[i:i+8],2))
        i = i + 8
    new_str = ''.join(map(chr,bytes_lst))
    return new_str

print "length of the plaintext ",len("A really secret message. Not for prying eyes.   ")
cipher_text = EME_E(T,K,"A really secret message. Not for prying eyes.   ")
print "cipher_text is ", cipher_text
print "length of cipher_text is ", len(cipher_text)
decipered_text = EME_D(T,K,cipher_text)
print "deciphered text is ", decipered_text

'''
# Decryption
decryption_suite = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
plain_text = decryption_suite.decrypt(cipher_text)
'''
