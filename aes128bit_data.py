# -*- coding: utf-8 -*-
"""
Created on Tue Dec 26 16:23:10 2017

@author: Kyle
128-bit AES key encryption/decryption data functions
not secure; absolutely NO warranty
"""

import base64

def b64tobytes(s):
    b64s = base64.b64decode(s)
    out = []
    for char in b64s:
        out.append(char)
        
    return out

def bytestob64(l):
    return base64.b64encode(bytearray(l))

def asciitobytes(s):
    out = []
    for char in s:
        out.append(ord(char))
        
    return out

def bytestoascii(l):
    out = ''
    for c in l:
        out += chr(c)
        
    return out