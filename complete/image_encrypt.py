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

    # create a AES block cipher, use ECB mode
    cipher = AES.new(K,AES.MODE_ECB)
    # Initial vector
    IV = ''
    for i in range(0,n):
        IV = IV + '0'

    # TO DO : L needs to time 2 later !
    L =  cipher.encrypt(IV)
    a = len(L)
    L = shift_left(L, 1)
    b = len(L)

    if a != b:
        print "length mismatch"

    count = 0
    PPP_list = [] # store all the PPP obtained
    for i in range(1,m+1):
        P_i = P[count * n :i*n]
        count = count + 1
        PP = strxor.strxor(P_i, shift_left(L,i-1))
        PPP = cipher.encrypt(PP)
        PPP_list.append(PPP)

    SP = " " * 16 # empty string
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

def shift_left(input_string,num_of_bits):
    input_length = len(input_string)
    # convert input string to binary string
    binary_str = ''.join('{0:08b}'.format(ord(x), 'b') for x in input_string)
    a = len(binary_str)
    firstbit = binary_str[0]
    binary_str = "{0:b}".format(int(binary_str, 2) << num_of_bits)
    b = len(binary_str)
    # shift out bits, python doesn't handle this
    if b > 128:
        binary_str = binary_str[-128:]
    # if old string is longer than the current one, 0s are ignored by python
    elif b < 128:
        while(len(binary_str) != 128):
            binary_str = '0' + binary_str
    const87 = '{0:0128b}'.format(87)
    # if first bit is 0 then do nothing
    if firstbit == '1':
        result = ""
        for i in range(0, 128):
            result = result + (str(int(binary_str[i]) ^ int(const87[i])))
        binary_str = result
    # convert back to unicode string
    bytes_lst = []
    i = 0
    while i < 128:
        bytes_lst.append(int(binary_str[i:i+8],2))
        i = i + 8
    new_str = ''.join(map(chr,bytes_lst))
    return new_str

import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from scipy import misc
from scipy import ndimage
import sys


# Usage python image_encrypt.py K T Image_path
if len(sys.argv) != 4:
    print "Usage python image_encrypt.py K T Image_path"
    sys.exit(0)

K = sys.argv[1]
T = sys.argv[2]
image_path = sys.argv[3]
if len(T) != 16:
    print 'Tweak Parameter length has to be 128 bits'
    sys.exit(0)
if len(K) != 16:
    print 'Key length has to be 128 bits'
    sys.exit(0)

import time
import sys

toolbar_width = 40
# sys.argv

image = mpimg.imread(image_path)
height = image.shape[0]
width = image.shape[1]

dimension = len(image[0][0])
print "encrypting image: ", image_path

message = ""
for j in range(0, height):
    for i in range(0, width):
        for k in image[j][i]:
            message = message + str(bytearray([int(round(k * 255.0))]))
cipher_text = ""
index = 0
while index < len(message):
    if index + 16*128 > len(message):
         cipher_text = cipher_text + EME_E(T,K,message[index:len(message)])
         break
    cipher_text = cipher_text + EME_E(T,K,message[index:index+16*128])
    index = index + 16*128
    
    binary_str = ''.join('{0:08b}'.format(ord(x), 'b') for x in T)
    binary_str = "{0:b}".format(int(binary_str, 2)+1)
    if len(binary_str) < 128:
        while(len(binary_str) != 128):
            binary_str = '0' + binary_str
    i = 0
    bytes_lst = []
    while i < 128:
        bytes_lst.append(int(binary_str[i:i+8],2))
        i = i + 8
    T = ''.join(map(chr,bytes_lst))
    # Print the progress bar
    sys.stdout.write('\r')
    sys.stdout.write("current progrss : %f%%" % (float(index)/len(message) * 100.0))
    sys.stdout.flush()
sys.stdout.write('\n')
sys.stdout.flush()

tmp = cipher_text
for j in range(0, height):
    for i in range(0, width):
        image[j][i] = [ord(cipher_text[0])/255.0, ord(cipher_text[1])/255.0, ord(cipher_text[2])/255.0, ord(cipher_text[3])/255.0]
        cipher_text = cipher_text[4:]
plt.imshow(image)
misc.imsave('encrypt.png', image)
plt.show()
