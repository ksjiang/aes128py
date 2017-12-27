# -*- coding: utf-8 -*-
"""
Created on Mon Dec 25 16:08:22 2017

@author: Kyle

128-bit AES key encryption/decryption
not secure; absolutely NO warranty
"""

import aes128bit_data
import aes128bit_tbl

def lookup(byte, table):
    return table[byte]

def s_box(byte):
    return lookup(byte, aes128bit_tbl.s_box)

def invs_box(byte):
    return lookup(byte, aes128bit_tbl.invs_box)

def gfmul(byte, n):
    if n == 1:
        #identity
        return byte
    if n == 2:
        return lookup(byte, aes128bit_tbl.gfmul2)
    if n == 3:
        return lookup(byte, aes128bit_tbl.gfmul3)
    if n == 9:
        return lookup(byte, aes128bit_tbl.gfmul9)
    if n == 11:
        return lookup(byte, aes128bit_tbl.gfmul11)
    if n == 13:
        return lookup(byte, aes128bit_tbl.gfmul13)
    if n == 14:
        return lookup(byte, aes128bit_tbl.gfmul14)

def rcon(val):
    return lookup(val, aes128bit_tbl.rcon)

class AESKey(object):
    def __init__(self, baseKey):
        #expecting value to be a char array
        if len(baseKey) < 16:
            raise ValueError("baseKey is too short (should be 16 bytes)")
        self.value = baseKey[: 16]
        return
    
    def __str__(self):
        s = ''
        for i in range(len(self.value)):
            s += str(format(self.value[i], "02X")) + ' '
            if not((i + 1) % 16):
                s += '\n'
                
        return s
    
    def getRoundKey(self, r):
        #round key 0 is the base key
        return AESKey(self.value[16 * r: 16 * (r + 1)])
    
    def isExpanded(self):
        if len(self.value) == 176:
            return True
        return False
    
    def expand(self):
        #helper function
        def expCore(seg, i):
            #expecting seg to be a 32-bit word and i an int
            
            #rotate bytes
            temp = seg[0]
            seg[0] = seg[1]
            seg[1] = seg[2]
            seg[2] = seg[3]
            seg[3] = temp
            
            #apply s-box
            for j in range(4):
                seg[j] = s_box(seg[j])
                
            #rcon
            seg[0] ^= rcon(i)
            
            return
            
        rconiter = 1
#        print(rconiter)
        while not self.isExpanded():
            t = self.value[-4: ]
            
            #perform core
            if not(len(self.value) % 16):
#                print(rconiter)
                expCore(t, rconiter)
                rconiter += 1
            
            #XOR and attach
            newBytes = []
            for k in range(4):
#                print(t[k])
                newBytes.append(self.value[-16 + k] ^ t[k])
                
            self.value += newBytes
            
        return
    
class AESText(object):
    def __init__(self, value, key):
        #value should be byte array
        self.setValue(value)
        #key should be AESKey object
        self.setKey(key)
        
        return
    
    def __str__(self):
        out = "Text: " + str(aes128bit_data.bytestoascii(self.value)) + '\n'
        out += "Key: " + str(self.key)
        return out
    
    def setValue(self, value):
        self.value = value
        return
    
    def getValue(self):
        return self.value
    
    def setKey(self, key):
        self.key = key
        return
    
    def getKey(self):
        return self.key
    
    def conStates(self):
        #returns tuple containing number of states and list of state objects (last one padded)
        n = len(self.value)
        l = []
        blocks = n // 16
        for i in range(blocks):
            l.append(State(self.value[16 * i: 16 * (i + 1)]))
            
        #pad with \x00s and build final state
        k = 16 - n % 16
        fin = self.value[16 * blocks: ]
        for i in range(k):
            fin.append(0)
            
        l.append(State(fin))
        
        return (blocks + 1, l)
    
    def encrypt(self):
        #form 16-byte states
        (i, l) = self.conStates()
        
        for j in range(i):
            l[j].enc(self.key)
            self.value[16 * j: 16 * (j + 1)] = l[j].value
            
        return
    
    def rempad(self):
        self.value[:] = [x for x in self.value if x != 0]
        return
    
    def decrypt(self):
        #form 16-byte states
        (i, l) = self.conStates()
        
        for j in range(i - 1):
            l[j].dec(self.key)
            self.value[16 * j: 16 * (j + 1)] = l[j].value
            
        self.rempad()
        
        return
    
class State(object):
    def __init__(self, value):
        self.value = value
        
        return
        
    def __str__(self):
        s = "Text: " + str(aes128bit_data.bytestoascii(self.value)) + '\n'
        for i in range(len(self.value)):
            s += str(format(self.value[i], "02X")) + ' '
            
        s += '\n'
                
        return s
        
    def addRoundKey(self, key):
        #expecting key a round key object
        for i in range(16):
            self.value[i] ^= key.value[i]
        
        return
    
    def subBytes(self):
        for i in range(16):
            self.value[i] = s_box(self.value[i])
            
        return
    
    def revSubBytes(self):
        for i in range(16):
            self.value[i] = invs_box(self.value[i])
            
        return
    
    def shift(self, vect):
        temp = []
        for i in range(16):
#            print(vect[i])
            temp.append(self.value[vect[i]])
            
        self.value = temp[:]
        
        return
    
    def shiftRows(self):
        vect = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        self.shift(vect)
        
        return
    
    def revShiftRows(self):
        revvect = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
        self.shift(revvect)
        
        return
    
    def mix(self, m):
        u = []
        for i in range(4):
            s = self.value[4 * i: 4 * (i + 1)]
            for j in range(4):
                t = m[4 * j: 4 * (j + 1)]
#                print(s[1])
#                print(t[1])
#                print(gfmul(s[1], t[1]))
                u.append(gfmul(s[0], t[0]) ^ gfmul(s[1], t[1]) ^ gfmul(s[2], t[2]) ^ gfmul(s[3], t[3]))
            
        self.value = u[:]
        
        return
    
    def mixColumns(self):
        matrix = [2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2]
        self.mix(matrix)
        
        return
        
    def revMixColumns(self):
        revmatrix = [14, 11, 13, 9, 9, 14, 11, 13, 13, 9, 14, 11, 11, 13, 9, 14]
        self.mix(revmatrix)
        
        return
        
    def enc(self, key):
        #expecting an expanded key... but if not then do it
        if not key.isExpanded():
            key.expand()
            
        #whiten
        self.addRoundKey(key.getRoundKey(0))
        
        #rounds 1 - 9
        for i in range(9):
            self.subBytes()
            self.shiftRows()
            self.mixColumns()
            self.addRoundKey(key.getRoundKey(i + 1))
            
        #round 10
        self.subBytes()
        self.shiftRows()
        self.addRoundKey(key.getRoundKey(10))
        
        return
    
    def dec(self, key):
        #expecting an expanded key... but if not then do it
        if not key.isExpanded():
            key.expand()
            
        self.addRoundKey(key.getRoundKey(10))
        self.revShiftRows()
        self.revSubBytes()
        
        for i in range(9):
            self.addRoundKey(key.getRoundKey(9 - i))
            self.revMixColumns()
            self.revShiftRows()
            self.revSubBytes()
            
        self.addRoundKey(key.getRoundKey(0))
        
        return
    
def encode(s, key):
    #expecting s an ASCII string and key a base64 string
    k = AESKey(aes128bit_data.b64tobytes(key))
    plaintext = AESText(aes128bit_data.asciitobytes(s), k)
    plaintext.encrypt()
    
    return aes128bit_data.bytestob64(plaintext.getValue())

def decode(s, key):
    #expecting both s and key base64 strings
    k = AESKey(aes128bit_data.b64tobytes(key))
    ciphertext = AESText(aes128bit_data.b64tobytes(s), k)
    ciphertext.decrypt()
    
    return aes128bit_data.bytestoascii(ciphertext.getValue())