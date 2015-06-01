# CSE191-Format-Preserved-Encryption
Format Preserved Encryption on Images

Complete version can be found in the complete/ folder.

Usage:

To encrypt an image:
python image_encrypt.py [Key of 128 bits] [Tweak of 128 bits] [Image Path]

To decrypt an image:
python image_decrypt.py [Key of 128 bits] [Tweak of 128 bits] [Image Path]

Notes:

1. Current version only supports .png file format

2. Size of images must satisfy total number of pixels are divisible by 4


Reference:

The Full paper covering Enciphering Algorithm: http://web.cs.ucdavis.edu/~rogaway/papers/eme.pdf

Original image: ![alt tag](https://github.com/RuiqingQiu/CSE191-Format-Preserved-Encryption/blob/master/test9.png) 

Encrypted image: ![alt tag](https://github.com/RuiqingQiu/CSE191-Format-Preserved-Encryption/blob/master/complete/encrypt.png)

Decrypted image: ![alt tag](https://github.com/RuiqingQiu/CSE191-Format-Preserved-Encryption/blob/master/complete/decrypt.png)
