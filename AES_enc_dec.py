from Crypto.Cipher import AES
from PIL import Image
import numpy as np
import secrets
import sys

# 픽셀값 리턴
def trans_format_RGB(data):
    red, green, blue = tuple(map(lambda e: [data[i] for i in range(0, len(data)) if i % 3 == e], [0, 1, 2]))
    pixels = tuple(zip(red, green, blue))
    return pixels

def list2hex(input):
    output = 0
    for i in range(8):
        output = output | (input[i] << (8 * i))
    return output

def string2hex(input): #문자열을 hex형태로 변환(아스키 표를 참조. ex) a -> 0x61, b -> 0x62...
    tmp = 0
    for i in range(len(input)): # 문자열 길이만큼 아래를 수행
        tmp  = (tmp << 8) | ord(input[i]) # ord함수를 통해 hex값 반환 (ord("a") = 0x61, ...)
    return tmp

# AES ECB 암호화
def AES_Enc_ECB(data, key):

    cipher = AES.new(key,AES.MODE_ECB)
    cipher_data = cipher.encrypt(data)
    
    return cipher_data

# AES ECB 복호화
def AES_Dec_ECB(data, key):

    cipher = AES.new(key,AES.MODE_ECB)
    recovered_data = cipher.decrypt(data)

    return recovered_data


# AES CTR 암호화
def AES_Enc_CTR(data, key, iv):
    
    cipher = AES.new(key,AES.MODE_CTR,nonce=iv)
    cipher_data = cipher.encrypt(data)

    return cipher_data

# AES CTR 복호화
def AES_Dec_Ctr(data, key, iv):

    cipher2 = AES.new(key,AES.MODE_CTR,nonce=iv)
    recovered_data = cipher2.decrypt(data)

    return recovered_data

# AES CBC 암호화
def AES_Enc_CBC(data, key, iv):

    cipher = AES.new(key,AES.MODE_CBC, iv)
    cipher_data = cipher.encrypt(data)

    return cipher_data

# AES CBC 복호화
def AES_Dec_CBC(data, key, iv):

    cipher = AES.new(key,AES.MODE_CBC, iv)
    recovered_data = cipher.decrypt(data)

    return recovered_data

# padding
def padding(data):
    if (len(data) % 16 == 0):
        return data
    else:
        padded_data = data + b'\x00' * (16 - len(data) % 16)
        return padded_data

# AES Enc
def AES128_Enc(openpath,savepath,mode,iv,key,nonce):
    key = key.to_bytes(16,'little')
    iv = iv.to_bytes(16,'little')
    nonce = nonce.to_bytes(8,'little')

    if ".png" in openpath:
        filetype = "image"
        im = Image.open(openpath)
        data = im.convert("RGB").tobytes()
        imlen = len(data)
        padding_data = padding(data)
    elif ".txt" in openpath:
        filetype = "txt"
        fp_read = open(openpath,"rb")
        data = fp_read.read()
        fp_read.close()
        padding_data = padding(data)           

        # padding_data = bytes(padding_data)

    if mode == "ECB" :
        cipher_data = AES_Enc_ECB(padding_data, key)
    elif mode == "CTR":
        cipher_data = AES_Enc_CTR(padding_data, key, nonce)
    elif mode == "CBC":
        cipher_data = AES_Enc_CBC(padding_data, key, iv)

    if filetype == "image":
        cipher_data_rgb = trans_format_RGB(cipher_data[:imlen])
        new = Image.new(im.mode, im.size)
        new.putdata(cipher_data_rgb)
        new.save(savepath+"\\img_" +"AES_" +mode + "_Enc.png")
    elif filetype == "txt":
        fp_write = open(savepath+"\\txt_" +"AES_" +mode + "_Enc.txt","wb")
        fp_write.write(cipher_data)
        fp_write.close()

# AES Dec
def AES128_Dec(openpath,savepath,mode,iv,key,nonce):
    #key = key.to_bytes(16,'little')
    key = 'key is KDFS 2020'
    iv = iv.to_bytes(16,'little')
    nonce = nonce.to_bytes(8,'little')
    if ".png" in openpath:
        filetype = "image"
        im = Image.open(openpath)
        data = im.convert("RGB").tobytes()
        imlen = len(data)
        padding_data = padding(data)
    elif ".txt" in openpath:
        filetype = "txt"
        fp_read = open(openpath,"rb")
        data = fp_read.read()
        fp_read.close()
        padding_data = padding(data)

    if mode == "ECB" :
        recovered_data = AES_Dec_ECB(padding_data, key)
    elif mode == "CTR":
        recovered_data = AES_Dec_Ctr(padding_data, key, nonce)
    elif mode == "CBC":
        recovered_data = AES_Dec_CBC(padding_data, key, iv)

    
    if filetype == "image":
        recovered_data_rgb = trans_format_RGB(recovered_data[:imlen])
        new_de = Image.new(im.mode, im.size)
        new_de.putdata(recovered_data_rgb)
        new_de.save(savepath+"\\img_"+"AES_" + mode + "_Dec" + ".png")
    elif filetype == "txt":
        fp_write = open(savepath+"\\txt_" +"AES_" +mode + "_Dec.txt","w",encoding = "utf-8")
        recovered_data = recovered_data.decode("utf-8")
        fp_write.write(recovered_data)
        fp_write.close()

#AES128_Enc("ECB")
#AES128_Dec("ECB")