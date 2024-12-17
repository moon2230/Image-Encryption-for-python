import PIPO
import secrets
import random
from PIL import Image
import numpy as np
import sys
#####################txt#######################
def trans_format_RGB(data):
    red, green, blue = tuple(map(lambda e: [data[i] for i in range(0, len(data)) if i % 3 == e], [0, 1, 2]))
    pixels = tuple(zip(red, green, blue))
    return pixels
#! PIPO CTR_MODE_txt

def PIPO_CTR_encrypt_txt(list_read,iv,key):

    int_padlen = 8 - len(list_read) % 8 if len(list_read) % 8 !=0 else 0
    list_padded_pt = [0 for cnt_i in range(int_padlen + len(list_read))]
    for cnt_i in range(len(list_read)):
        list_padded_pt[cnt_i] = ord(list_read[cnt_i])
    for cnt_i in range(int_padlen):
        list_padded_pt[len(list_read) + cnt_i] = ord('0')
  
    list_ct = PIPO.pipo_ctr_enc(list_padded_pt,iv,key)

    list_ct = [chr(cnt_i) for cnt_i in list_ct]
    string_ct = ''.join(list_ct)

    return string_ct

def PIPO_CTR_decrypt_txt(list_read,iv,key):

    int_padlen = 8 - len(list_read) % 8 if len(list_read) % 8 !=0 else 0
    list_padded_ct = [0 for cnt_i in range(int_padlen + len(list_read))]
    for cnt_i in range(len(list_read)):
        list_padded_ct[cnt_i] = ord(list_read[cnt_i])
    for cnt_i in range(int_padlen):
        list_padded_ct[len(list_read) + cnt_i] = ord('0')
  
    list_re = PIPO.pipo_ctr_dec(list_padded_ct,iv,key)

    list_re = [chr(cnt_i) for cnt_i in list_re]
    string_re = ''.join(list_re)

    return string_re

#! PIPO ECB_MODE_txt

def PIPO_ECB_encrypt_txt(list_read,key):

    int_padlen = 8 - len(list_read) % 8 if len(list_read) % 8 !=0 else 0
    list_padded_pt = [0 for cnt_i in range(int_padlen + len(list_read))]
    for cnt_i in range(len(list_read)):
        list_padded_pt[cnt_i] = ord(list_read[cnt_i])
    for cnt_i in range(int_padlen):
        list_padded_pt[len(list_read) + cnt_i] = ord('0')
  
    list_ct = PIPO.pipo_ecb_enc(list_padded_pt,key)

    list_ct = [chr(cnt_i) for cnt_i in list_ct]
    string_ct = ''.join(list_ct)
    
    return string_ct

def PIPO_ECB_decrypt_txt(list_read,key):

    int_padlen = 8 - len(list_read) % 8 if len(list_read) % 8 !=0 else 0
    list_padded_ct = [0 for cnt_i in range(int_padlen + len(list_read))]
    for cnt_i in range(len(list_read)):
        list_padded_ct[cnt_i] = ord(list_read[cnt_i])
    for cnt_i in range(int_padlen):
        list_padded_ct[len(list_read) + cnt_i] = ord('0')
  
    list_re = PIPO.pipo_ecb_dec(list_padded_ct,key)

    list_re = [chr(cnt_i) for cnt_i in list_re]
    string_re = ''.join(list_re)

    return string_re
#! PIPO CBC_MODE_txt

def PIPO_CBC_encrypt_txt(list_read,iv,key):

    int_padlen = 8 - len(list_read) % 8 if len(list_read) % 8 !=0 else 0
    list_padded_pt = [0 for cnt_i in range(int_padlen + len(list_read))]
    for cnt_i in range(len(list_read)):
        list_padded_pt[cnt_i] = ord(list_read[cnt_i])
    for cnt_i in range(int_padlen):
        list_padded_pt[len(list_read) + cnt_i] = ord('0')
  
    list_ct = PIPO.pipo_cbc_enc(list_padded_pt,iv,key)

    list_ct = [chr(cnt_i) for cnt_i in list_ct]
    string_ct = ''.join(list_ct)
    return string_ct

def PIPO_CBC_decrypt_txt(list_read,iv,key):

    int_padlen = 8 - len(list_read) % 8 if len(list_read) % 8 !=0 else 0
    list_padded_ct = [0 for cnt_i in range(int_padlen + len(list_read))]
    for cnt_i in range(len(list_read)):
        list_padded_ct[cnt_i] = ord(list_read[cnt_i])
    for cnt_i in range(int_padlen):
        list_padded_ct[len(list_read) + cnt_i] = ord('0')
  
    list_re = PIPO.pipo_cbc_dec(list_padded_ct,iv,key)
    
    list_re = [chr(cnt_i) for cnt_i in list_re]
    string_re = ''.join(list_re)
    
    return string_re
#####################image##############################

#! PIPO CTR_MODE_image

def PIPO_CTR_encrypt_image(in_image, iv, key):

    list_read = in_image
    int_padlen = 8 - len(list_read) % 8 if len(list_read) % 8 !=0 else 0
    list_padded_pt = [0 for cnt_i in range(int_padlen + len(list_read))]
    for cnt_i in range(len(list_read)):
        list_padded_pt[cnt_i] = list_read[cnt_i]
  
    list_ct = PIPO.pipo_ctr_enc(list_padded_pt,iv,key)

    return list_ct

def PIPO_CTR_decrypt_image(in_image, iv, key):
    list_read = in_image

    int_padlen = 8 - len(list_read) % 8 if len(list_read) % 8 !=0 else 0
    list_padded_ct = [0 for cnt_i in range(int_padlen + len(list_read))]
    for cnt_i in range(len(list_read)):
        list_padded_ct[cnt_i] = list_read[cnt_i]
  
    list_re = PIPO.pipo_ctr_dec(list_padded_ct,iv,key)

    return list_re

#! PIPO ECB_MODE_image

def PIPO_ECB_encrypt_image(in_image, key):
    list_read = in_image

    int_padlen = 8 - len(list_read) % 8 if len(list_read) % 8 !=0 else 0
    list_padded_pt = [0 for cnt_i in range(int_padlen + len(list_read))]
    for cnt_i in range(len(list_read)):
        list_padded_pt[cnt_i] = list_read[cnt_i]
  
    list_ct = PIPO.pipo_ecb_enc(list_padded_pt,key)

    return list_ct

def PIPO_ECB_decrypt_image(in_image, key):
    list_read = in_image

    int_padlen = 8 - len(list_read) % 8 if len(list_read) % 8 !=0 else 0
    list_padded_ct = [0 for cnt_i in range(int_padlen + len(list_read))]
    for cnt_i in range(len(list_read)):
        list_padded_ct[cnt_i] = list_read[cnt_i]
  
    list_re = PIPO.pipo_ecb_dec(list_padded_ct,key)
    return list_re

#! PIPO CBC_MODE_image

def PIPO_CBC_encrypt_image(in_image, iv, key):
    list_read = in_image

    int_padlen = 8 - len(list_read) % 8 if len(list_read) % 8 !=0 else 0
    list_padded_pt = [0 for cnt_i in range(int_padlen + len(list_read))]
    for cnt_i in range(len(list_read)):
        list_padded_pt[cnt_i] = list_read[cnt_i]
  
    list_ct = PIPO.pipo_cbc_enc(list_padded_pt,iv,key)

    return list_ct

def PIPO_CBC_decrypt_image(in_image, iv, key):
    list_read = in_image

    int_padlen = 8 - len(list_read) % 8 if len(list_read) % 8 !=0 else 0
    list_padded_ct = [0 for cnt_i in range(int_padlen + len(list_read))]
    for cnt_i in range(len(list_read)):
        list_padded_ct[cnt_i] = list_read[cnt_i]
  
    list_re = PIPO.pipo_cbc_dec(list_padded_ct,iv,key)

    return list_re

def PIPO_ENC(openpath,savepath,mode, int_iv, int_key):
    if ".png" in openpath:
        filetype = "image"
        im = Image.open(openpath)
        data = im.convert("RGB").tobytes()
        imlen = len(data)
    elif ".txt" in openpath:
        filetype = "txt"
        fp_read = open(openpath,"r")
        data = fp_read.read()
        fp_read.close()
        
    

    if mode == "CTR":
        if filetype == "image":
            cipher_data = PIPO_CTR_encrypt_image(data,int_iv,int_key)
        elif filetype == "txt":
            cipher_data = PIPO_CTR_encrypt_txt(data,int_iv,int_key)

    elif mode == "ECB":
        if filetype == "image":
            cipher_data = PIPO_ECB_encrypt_image(data,int_key)
        elif filetype == "txt":
            cipher_data = PIPO_ECB_encrypt_txt(data,int_key)

    elif mode == "CBC":
        if filetype == "image":
            cipher_data = PIPO_CBC_encrypt_image(data,int_iv,int_key)
        elif filetype == "txt":
            cipher_data = PIPO_CBC_encrypt_txt(data,int_iv,int_key)

    if filetype == "image":
        cipher_data_rgb = trans_format_RGB(cipher_data[:imlen])
        new = Image.new(im.mode, im.size)
        new.putdata(cipher_data_rgb)
        new.save(savepath+"\\img_" +"PIPO_" +mode + "_Enc.png")
    elif filetype == "txt":
        fp_write = open(savepath+"\\txt_" +"PIPO_" +mode + "_Enc.txt","w",encoding='utf-8')
        fp_write.write(cipher_data)
        fp_write.close()

    

def PIPO_DEC(openpath,savepath,mode, int_iv, int_key):

    if ".png" in openpath:
        filetype = "image"
        im = Image.open(openpath)
        data = im.convert("RGB").tobytes()
        imlen = len(data)
    elif ".txt" in openpath:
        filetype = "txt"
        fp_read = open(openpath,"r",encoding='utf-8')
        data = fp_read.read()
        fp_read.close()

    if mode == "CTR":
        if filetype == "image":
            cipher_data = PIPO_CTR_decrypt_image(data,int_iv,int_key)
        elif filetype == "txt":
            cipher_data = PIPO_CTR_decrypt_txt(data,int_iv,int_key)

    elif mode == "ECB":
        if filetype == "image":
            cipher_data = PIPO_ECB_decrypt_image(data,int_key)
        elif filetype == "txt":
            cipher_data = PIPO_ECB_decrypt_txt(data,int_key)

    elif mode == "CBC":
        if filetype == "image":
            cipher_data = PIPO_CBC_decrypt_image(data,int_iv,int_key)
        elif filetype == "txt":
            cipher_data = PIPO_CBC_decrypt_txt(data,int_iv,int_key)

    if filetype == "image":
        recovered_data_rgb = trans_format_RGB(cipher_data[:imlen])
        new_de = Image.new(im.mode, im.size)
        new_de.putdata(recovered_data_rgb)
        new_de.save(savepath+"\\img_"+"PIPO_" + mode + "_Dec" + ".png")
    elif filetype == "txt":
        fp_write = open(savepath+"\\txt_" +"PIPO_" +mode + "_Dec.txt","w",encoding='utf-8')
        fp_write.write(cipher_data)
        fp_write.close()

if __name__ == '__main__':

    # ! Parameter #########################################################
    int_key = secrets.randbits(128)
    int_iv = secrets.randbits(128)

    PIPO_ENC("CTR","image",int_iv,int_key)
    PIPO_DEC("CTR","image",int_iv,int_key)

    PIPO_ENC("ECB","image",int_iv,int_key)
    PIPO_DEC("ECB","image",int_iv,int_key)

    PIPO_ENC("CBC","image",int_iv,int_key)
    PIPO_DEC("CBC","image",int_iv,int_key)
