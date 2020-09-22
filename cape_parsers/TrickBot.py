#! /usr/bin/env python
# Slavo Greminger, 2019/01
# TLP AMBER
# - extract static configuration from xor-"encrypted" data blob and then uses hasherezade's stuff
# - Added 64-bit support. Needed to add code to account for 64-bit uses relative addressing. [Steeve Gaudreault, CCCS, May 8 2019]
# - Updated to decrypt latest config using the new 8 byte key, only 32-bit [Chad McNamara,Steeve Gaudreault, CCCS, July 8th 2019]
 
import binascii
import pefile
import re
import struct
import sys
 
import hashlib
from Crypto.Cipher import AES
 
### data config/res
trickbot_addr_config = [
    #32bit
(
    r"(?P<instructions_begin>(\x83\x7D\x0C\x00\xBE))"
    r"(?P<data_len>([\S\s]{2}))"
    r"(?P<instructions>(\x00\x00\x74[\x10-\x1F]\xFF\x75\x0C\x56\x68))" 
    r"(?P<data_addr>([\S\s]{4}))"
    r"(?P<instructions_end>(\xE8))"
),
  #32-bit 2 2019-07-08 (8 byte key)
 (
    r"(?P<instructions_begin>(\xB8))"
    r"(?P<data_len>([\S\s]{4}))"
    r"(?P<instructions>(\x85\xC9\x74([\x10-\x1F]|\x32)))"
    r"(?P<byte_beforeKeyLen>(\xBE))"
    r"(?P<key_len>([\S\s]{4}))"
    r"(?P<byte_beforeKey>(\xBA))"
    r"(?P<xor_key>([\S\s]{4}))"
    r"(?P<extra_byte>(\xBF))"
    r"(?P<data_address>([\S\s]{4}))"
    r"(?P<instructions_end>(\xBB))"
),
    #64bit (rip)
(
    r"(?P<instructions_begin>(\xC7\x44\x24\x20))"
    r"(?P<data_len>([\S\s]{2}))"
    r"(?P<instructions>(\x00\x00\x48[\S\s]{4}\x00[\x74\x75][\S\s]\x4C[\S\s]{4,10}\x48\x8D\x0D))" 
    r"(?P<data_addr>([\S\s]{4}))"
    r"(?P<instructions_end>(\xE8))"
),
]
### xor key
trickbot_addr_xorkey = [
    #32bit
(
    r"(?P<instructions_begin>(\x8B\x3D))"
    r"(?P<xorkey_addr_len>([\S\s]{4}))"
    r"(?P<instructions_1n>(\x83\xE0\xFC\x03\xC1\xBE))"
    r"(?P<xorkey_addr_a>([\S\s]{4}))"
    r"(?P<instructions_2>(\x8D\xBF))" 
    r"(?P<xorkey_addr_b>([\S\s]{4}))"
    
),
    #64bit
(
    r"(?P<instructions_begin>(\x48\x8B[\S\s]{3}\x48\x89[\S\s]{3}\x48\x8D[\x00-\x0F]))"
    r"(?P<xorkey_addr_a>([\S\s]{4}))"
    r"(?P<instructions_1n>(\x48\x89[\S\s]{3}\x8B[\x00-\x0F]))"
    r"(?P<xorkey_addr_len>([\S\s]{4}))"
    r"(?P<instructions_2>(\x48\x8B[\S\s]{3}\x48\x03\xC8))" 
    
),
]
 
#### hasherezade
def derive_key(n_rounds,input_bf):
    intermediate = input_bf
    for i in range(0, n_rounds):
        sha = hashlib.sha256()
        sha.update(intermediate)
        current = sha.digest()
        intermediate += current
    return current
def trick_decrypt(data):
    key = derive_key(128, data[:32])
    iv = derive_key(128,data[16:48])[:16]
    aes = AES.new(key, AES.MODE_CBC, iv)
    mod = len(data[48:]) % 16
    if mod != 0:
        data += '0' * (16 - mod)
    return aes.decrypt(data[48:])[:-(16-mod)]
#### hasherezade
 
def trick_decrypt_xor(pe_data):

    pe = pefile.PE(data=pe_data)
    pedata = pe.get_memory_mapped_image()
    #tricky thing ... 64-bit uses relative addressing vs Absolute, let's track the architecture
    if pe.OPTIONAL_HEADER.Magic == 0x10b: # = 32bit
        ArchFlag = 0
    else:
        ArchFlag = 1
    data = None
    key = None
    key_len = None
    for regex in trickbot_addr_config:
        print(regex.encode('utf-8'))
        res = re.finditer(regex.encode('utf-8'),pedata,re.DOTALL)
        if res:
            for match in res:
                t=match.groupdict()
                if t:
                    try:
                        data_len = struct.unpack("<H",t["data_len"])[0]
                        data_addr = struct.unpack("<I",t["data_addr"])[0]
                        # Here Extracted address and Code are in the same section.
                        # readjusting if in 64-bit
                        if ArchFlag: 
                            data_addr = match.start()-(0xffffffff - int(data_addr))+0x1f  #my sample had negative reference, may need to adjust if need be
                        else:
                            data_addr -= pe.OPTIONAL_HEADER.ImageBase
                        data = pe.get_data(data_addr,data_len)
                        #print"Hit: 0x%x"%(match.start()+pe.OPTIONAL_HEADER.ImageBase)
                        #print("Addr: 0x%x"%(data_addr))                        
                    except Exception:
                        data_len = struct.unpack("<HH",t["data_len"])[0]
                        data_addr = struct.unpack("<I",t["data_address"])[0]
                        xorkey_addr = struct.unpack("<I",t["xor_key"])[0]
                        key_len = struct.unpack("<HH", t["key_len"])[0]
                        # Here Extracted address and Code are in the same section.
                        # readjusting if in 64-bit
                        if ArchFlag: 
                            data_addr = match.start()-(0xffffffff - int(data_addr))+0x1f  #my sample had negative reference, may need to adjust if need be
                        else:
                            data_addr -= pe.OPTIONAL_HEADER.ImageBase
                            xorkey_addr -= pe.OPTIONAL_HEADER.ImageBase
                        
                        data = pe.get_data(data_addr,data_len)
                        key = pe.get_data(xorkey_addr, key_len)
                        
            
    # look for xorkey
    for regex in trickbot_addr_xorkey:
        #using pe mapped data because the xor key is in the data section, easier to calculate offsets
        res = re.finditer(regex.encode('utf-8'),pedata,re.DOTALL)
        if res:
            for match in res:
                t=match.groupdict()
                if t:
                    xorkey_addr_len = struct.unpack("<I",t["xorkey_addr_len"])[0]
                    xorkey_addr_a = struct.unpack("<I",t["xorkey_addr_a"])[0]
                    #xorkey_addr_b = struct.unpack("<I",t["xorkey_addr_b"])[0]
                    if ArchFlag:
                        xorkey_addr_a += match.start() + 0x11 
                        xorkey_addr_len += match.start() + 0x1C 
                    else:
                        xorkey_addr_a -= pe.OPTIONAL_HEADER.ImageBase 
                        xorkey_addr_len -= pe.OPTIONAL_HEADER.ImageBase 
                    #print("Xor1: 0x%x"%(int(xorkey_addr_a)))
                    #print("Match: 0x%x"%match.start())
                    #print("AddrXorKeyLen: 0x%x"%int(xorkey_addr_len))
                    xorkey_len = struct.unpack("<I",pe.get_data(xorkey_addr_len,4))[0]
                    #print("KeyLen: 0x%x"%xorkey_len)
                    key = pe.get_data(xorkey_addr_a,xorkey_len)
                    key_len = len(key)
    
    if not data or not key:
        return ""
    # decrypt (only additional xor layer)
    dexored = []
    i = 0
    for each in data:
        dexored.append((each^key[i%key_len])&0xff)
        i += 1
    # use hasherezade's code
    decrypted = trick_decrypt(bytes(dexored))
    return(decrypted[8:8+struct.unpack('<I',decrypted[0:4])[0]])
def config(data):
    return trick_decrypt_xor(data)

