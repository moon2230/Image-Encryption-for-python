import random
import secrets
# 구현할 block cipher : pipo-128

# 블록 사이즈 : 64 bits

# 키 사이즈 : 128/256bits

# 라운드 수 : 13/17

# 라운드 함수 : sbox, r-layer, key addition 순서대로 진행

#128bits 라운드 키 기준으로 코드 작성!

# 키스케쥴링 : |K| = 128 -> K = K1||K0 (|K1| = |K0| = 64)

# pipo의 sbox
sbox = [0x5E, 0xF9, 0xFC, 0x00, 0x3F, 0x85, 0xBA, 0x5B, 0x18, 0x37, 0xB2, 0xC6, 0x71, 0xC3, 0x74, 0x9D,
   0xA7, 0x94, 0x0D, 0xE1, 0xCA, 0x68, 0x53, 0x2E, 0x49, 0x62, 0xEB, 0x97, 0xA4, 0x0E, 0x2D, 0xD0,
   0x16, 0x25, 0xAC, 0x48, 0x63, 0xD1, 0xEA, 0x8F, 0xF7, 0x40, 0x45, 0xB1, 0x9E, 0x34, 0x1B, 0xF2,
   0xB9, 0x86, 0x03, 0x7F, 0xD8, 0x7A, 0xDD, 0x3C, 0xE0, 0xCB, 0x52, 0x26, 0x15, 0xAF, 0x8C, 0x69,
   0xC2, 0x75, 0x70, 0x1C, 0x33, 0x99, 0xB6, 0xC7, 0x04, 0x3B, 0xBE, 0x5A, 0xFD, 0x5F, 0xF8, 0x81,
   0x93, 0xA0, 0x29, 0x4D, 0x66, 0xD4, 0xEF, 0x0A, 0xE5, 0xCE, 0x57, 0xA3, 0x90, 0x2A, 0x09, 0x6C,
   0x22, 0x11, 0x88, 0xE4, 0xCF, 0x6D, 0x56, 0xAB, 0x7B, 0xDC, 0xD9, 0xBD, 0x82, 0x38, 0x07, 0x7E,
   0xB5, 0x9A, 0x1F, 0xF3, 0x44, 0xF6, 0x41, 0x30, 0x4C, 0x67, 0xEE, 0x12, 0x21, 0x8B, 0xA8, 0xD5,
   0x55, 0x6E, 0xE7, 0x0B, 0x28, 0x92, 0xA1, 0xCC, 0x2B, 0x08, 0x91, 0xED, 0xD6, 0x64, 0x4F, 0xA2,
   0xBC, 0x83, 0x06, 0xFA, 0x5D, 0xFF, 0x58, 0x39, 0x72, 0xC5, 0xC0, 0xB4, 0x9B, 0x31, 0x1E, 0x77,
   0x01, 0x3E, 0xBB, 0xDF, 0x78, 0xDA, 0x7D, 0x84, 0x50, 0x6B, 0xE2, 0x8E, 0xAD, 0x17, 0x24, 0xC9,
   0xAE, 0x8D, 0x14, 0xE8, 0xD3, 0x61, 0x4A, 0x27, 0x47, 0xF0, 0xF5, 0x19, 0x36, 0x9C, 0xB3, 0x42,
   0x1D, 0x32, 0xB7, 0x43, 0xF4, 0x46, 0xF1, 0x98, 0xEC, 0xD7, 0x4E, 0xAA, 0x89, 0x23, 0x10, 0x65,
   0x8A, 0xA9, 0x20, 0x54, 0x6F, 0xCD, 0xE6, 0x13, 0xDB, 0x7C, 0x79, 0x05, 0x3A, 0x80, 0xBF, 0xDE,
   0xE9, 0xD2, 0x4B, 0x2F, 0x0C, 0xA6, 0x95, 0x60, 0x0F, 0x2C, 0xA5, 0x51, 0x6A, 0xC8, 0xE3, 0x96,
   0xB0, 0x9F, 0x1A, 0x76, 0xC1, 0x73, 0xC4, 0x35, 0xFE, 0x59, 0x5C, 0xB8, 0x87, 0x3D, 0x02, 0xFB]

rsbox = [ 0x03, 0xA0, 0xFE, 0x32, 0x48, 0xDB, 0x92, 0x6E, 0x89, 0x5E, 0x57, 0x83, 0xE4, 0x12, 0x1D, 0xE8, 0xCE, 0x61, 0x7B, 0xD7, 0xB2, 0x3C, 0x20, 0xAD, 0x08, 0xBB, 0xF2, 0x2E, 0x43, 0xC0, 0x9E, 0x72, 0xD2, 0x7C, 0x60, 0xCD, 0xAE, 0x21, 0x3B, 0xB7, 0x84, 0x52, 0x5D, 0x88, 0xE9, 0x1E, 0x17, 0xE3, 0x77, 0x9D, 0xC1, 0x44, 0x2D, 0xF7, 0xBC, 0x09, 0x6D, 0x97, 0xDC, 0x49, 0x37, 0xFD, 0xA1, 0x04, 0x29, 0x76, 0xBF, 0xC3, 0x74, 0x2A, 0xC5, 0xB8, 0x23, 0x18, 0xB6, 0xE2, 0x78, 0x53, 0xCA, 0x8E, 0xA8, 0xEB, 0x3A, 0x16, 0xD3, 0x80, 0x66, 0x5A, 0x96, 0xF9, 0x4B, 0x07, 0xFA, 0x94, 0x00, 0x4D, 0xE7, 0xB5, 0x19, 0x24, 0x8D, 0xCF, 0x54, 0x79, 0x15, 0x3F, 0xEC, 0xA9, 0x5F, 0x65, 0x81, 0xD4, 0x42, 0x0C, 0x98, 0xF5, 0x0E, 0x41, 0xF3, 0x9F, 0xA4, 0xDA, 0x35, 0x68, 0xD9, 0xA6, 0x6F, 0x33, 0xDD, 0x4F, 0x6C, 0x91, 0xA7, 0x05, 0x31, 0xFC, 0x62, 0xCC, 0xD0, 0x7D, 0x3E, 0xB1, 0xAB, 0x27, 0x5C, 0x8A, 0x85, 0x50, 0x11, 0xE6, 0xEF, 0x1B, 0xC7, 0x45, 0x71, 0x9C, 0xBD, 0x0F, 0x2C, 0xF1, 0x51, 0x86, 0x8F, 0x5B, 0x1C, 0xEA, 0xE5, 0x10, 0x7E, 0xD1, 0xCB, 0x67, 0x22, 0xAC, 0xB0, 0x3D, 0xF0, 0x2B, 0x0A, 0xBE, 0x9B, 0x70, 0x46, 0xC2, 0xFB, 0x30, 0x06, 0xA2, 0x90, 0x6B, 0x4A, 0xDE, 0x9A, 0xF4, 0x40, 0x0D, 0xF6, 0x99, 0x0B, 0x47, 0xED, 0xAF, 0x14, 0x39, 0x87, 0xD5, 0x59, 0x64, 0x1F, 0x25, 0xE1, 0xB4, 0x55, 0x7F, 0x8C, 0xC9, 0x34, 0x6A, 0xA5, 0xD8, 0x69, 0x36, 0xDF, 0xA3, 0x38, 0x13, 0xAA, 0xEE, 0x63, 0x58, 0xD6, 0x82, 0xB3, 0xE0, 0x26, 0x1A, 0xC8, 0x8B, 0x7A, 0x56, 0xB9, 0xC6, 0x2F, 0x73, 0xC4, 0xBA, 0x75, 0x28, 0x4E, 0x01, 0x93, 0xFF, 0x02, 0x4C, 0xF8, 0x95]

def print_list(input, text):
    print("%s" %text, end=" ")
    for i in range(len(input)):
        print(hex(input[i]), end=" ")

def string2hex(input): #문자열을 hex형태로 변환(아스키 표를 참조. ex) a -> 0x61, b -> 0x62...
    tmp = 0
    for i in range(len(input)): # 문자열 길이만큼 아래를 수행
        tmp  = (tmp << 8) | ord(input[i]) # ord함수를 통해 hex값 반환 (ord("a") = 0x61, ...)
    return tmp

def hex2list(input):
    tmp_list = [0 for i in range(8)]
    for i in range(8):
        tmp_list[i] = (input >> (8 * i)) & 0xff
    return tmp_list

def list2hex(input):
    output = 0
    for i in range(8):
        output = output | (input[i] << (8 * i))
    return output

def left_rotation(input, k):
    output = ((input << k) & 0xff) | ((input >> (8 - k)) & 0xff)
    return output

def right_rotation(input, k):
    output = ((input >> k) & 0xff) | ((input << (8 - k)) & 0xff)
    return output

def key_schedule(key128):
    roundkey_list = [0 for i in range(14)]
    k0 = key128 & 0xffffffffffffffff
    k1 = key128 >> 64
    tmp_list = [k0, k1]
    for i in range(14):
        roundkey_list[i] = tmp_list[i % 2] ^ i
    return roundkey_list

def s_layer(input):
    tmp = [0 for i in range(8)]
    output = [0 for i in range(8)]
    for i in range(8):
        tmp[i] = ((input[0] >> (7-i)) & 1) | (((input[1] >> (7-i)) & 1) << 1) | (((input[2] >> (7-i)) & 1) << 2) | (((input[3] >> (7-i)) & 1) << 3) | (((input[4] >> (7-i)) & 1) << 4) | (((input[5] >> (7-i)) & 1) << 5) | (((input[6] >> (7-i)) & 1) << 6) | (((input[7] >> (7-i)) & 1) << 7)
        tmp[i] = sbox[tmp[i]]
    for i in range(8):
        output[i] = (((tmp[0] >> i) & 1) << 7) | (((tmp[1] >> i) & 1) << 6) | (((tmp[2] >> i) & 1) << 5) | (((tmp[3] >> i) & 1) << 4) | (((tmp[4] >> i) & 1) << 3) | (((tmp[5] >> i) & 1) << 2) | (((tmp[6] >> i) & 1) << 1) | (((tmp[7] >> i) & 1) << 0)
    return output

def inv_s_layer(input):
    tmp = [0 for i in range(8)]
    output = [0 for i in range(8)]
    for i in range(8):
        tmp[i] = ((input[0] >> (7-i)) & 1) | (((input[1] >> (7-i)) & 1) << 1) | (((input[2] >> (7-i)) & 1) << 2) | (((input[3] >> (7-i)) & 1) << 3) | (((input[4] >> (7-i)) & 1) << 4) | (((input[5] >> (7-i)) & 1) << 5) | (((input[6] >> (7-i)) & 1) << 6) | (((input[7] >> (7-i)) & 1) << 7)
        tmp[i] = rsbox[tmp[i]]
    for i in range(8):
        output[i] = (((tmp[0] >> i) & 1) << 7) | (((tmp[1] >> i) & 1) << 6) | (((tmp[2] >> i) & 1) << 5) | (((tmp[3] >> i) & 1) << 4) | (((tmp[4] >> i) & 1) << 3) | (((tmp[5] >> i) & 1) << 2) | (((tmp[6] >> i) & 1) << 1) | (((tmp[7] >> i) & 1) << 0)
    return output

def r_layer(input):
    input[0] = input[0]
    input[1] = left_rotation(input[1], 7)
    input[2] = left_rotation(input[2], 4)
    input[3] = left_rotation(input[3], 3)
    input[4] = left_rotation(input[4], 6)
    input[5] = left_rotation(input[5], 5)
    input[6] = left_rotation(input[6], 1)
    input[7] = left_rotation(input[7], 2)
    return input

def inv_r_layer(input):
    input[0] = input[0]
    input[1] = right_rotation(input[1], 7)
    input[2] = right_rotation(input[2], 4)
    input[3] = right_rotation(input[3], 3)
    input[4] = right_rotation(input[4], 6)
    input[5] = right_rotation(input[5], 5)
    input[6] = right_rotation(input[6], 1)
    input[7] = right_rotation(input[7], 2)
    return input

def key_xor(input, roundkey):
    tmp_list = hex2list(roundkey)
    output = [0 for i in range(8)]
    for i in range(len(input)):
        output[i] = input[i] ^ tmp_list[i]
    return output

def Padding(pt):
    if(len(pt)% 8 == 0):
        return pt
    else:
        block_size = 8
        block_num = (len(pt) + block_size) // block_size
        pad_pt = [0 for i in range(block_num * block_size)]
        pad_pt[0:len(pt)]=pt
        return pad_pt

#! PIPO encryption
def pipo_128(plain, key):
    plain_list = hex2list(plain)
    roundkey = key_schedule(key)
    
    plain_list = key_xor(plain_list, roundkey[0])

    for i in range(1, 14):
        plain_list = s_layer(plain_list)
        plain_list = r_layer(plain_list)
        plain_list = key_xor(plain_list, roundkey[i])
    ciphertext = list2hex(plain_list)
    return ciphertext

#! PIPO decryption
def pipo_128_dec(int_ct, int_key):
    list_ct = hex2list(int_ct)
    roundkey = key_schedule(int_key)
    
    for i in range(13,0,-1):
        list_ct = key_xor(list_ct, roundkey[i])
        list_ct = inv_r_layer(list_ct)
        list_ct = inv_s_layer(list_ct)

    list_ct = key_xor(list_ct, roundkey[0])
    recovered = list2hex(list_ct)
    return recovered

#! PIPO CTR_MODE
def pipo_ctr_enc(list_pt, int_iv, int_key):
    
    list_ct = []
    list_tmp = []
    int_index = 0
    for cnt_i in range(int(len(list_pt) / 8)):
        buf = [list_pt[cnt_j + int_index] for cnt_j in range(8)]
        int_index += 8
        int_dst = pipo_128(int_iv,int_key)
        list_tmp = hex2list(int_dst)
        for cnt_j in range(8):
            buf[cnt_j] ^= list_tmp[cnt_j]
        list_ct += buf
        int_iv += 1

    return list_ct

def pipo_ctr_dec(list_pt, int_iv, int_key):
    
    list_ct = []
    list_tmp = []
    int_index = 0
    for cnt_i in range(int(len(list_pt) / 8)):
        buf = [list_pt[cnt_j + int_index] for cnt_j in range(8)]
        int_index += 8

        int_dst = pipo_128(int_iv,int_key)
        list_tmp = hex2list(int_dst)
        for cnt_j in range(8):
            buf[cnt_j] ^= list_tmp[cnt_j]
        list_ct += buf
        int_iv += 1

    return list_ct

#! PIPO ECB_MODE

def pipo_ecb_enc(list_pt, int_key):
    
    list_ct = []
    int_index = 0
    list_pt = Padding(list_pt)

    for cnt_i in range(int(len(list_pt) / 8)):
        buf = [list_pt[cnt_j + int_index] for cnt_j in range(8)]
        int_index += 8
        buf = list2hex(buf)
        int_dst = pipo_128(buf,int_key)
        list_ct += hex2list(int_dst)

    return list_ct

def pipo_ecb_dec(list_pt, int_key):
    
    list_ct = []
    int_index = 0
    list_pt = Padding(list_pt)

    for cnt_i in range(int(len(list_pt) / 8)):
        buf = [list_pt[cnt_j + int_index] for cnt_j in range(8)]
        int_index += 8
        buf = list2hex(buf)
        int_dst = pipo_128_dec(buf,int_key)
        list_ct += hex2list(int_dst)

    return list_ct

#! PIPO CBC_MODE

def pipo_cbc_enc(list_pt, int_iv, int_key):
    
    list_ct = []
    list_tmp = []
    list_iv = []
    int_index = 0
    list_pt = Padding(list_pt)

    for cnt_i in range(int(len(list_pt) / 8)):
        buf = [list_pt[cnt_j + int_index] for cnt_j in range(8)]
        int_index += 8
        list_iv = hex2list(int_iv)
        for cnt_j in range(8):
            buf[cnt_j] ^= list_iv[cnt_j]
        buf = list2hex(buf)
        int_dst = pipo_128(buf,int_key)
        int_iv = int_dst
        list_tmp = hex2list(int_dst)
        list_ct += list_tmp
    return list_ct


def pipo_cbc_dec(list_pt, int_iv, int_key):
    
    list_ct = []
    list_tmp = []
    list_iv = []
    int_index = 0
    list_pt = Padding(list_pt)

    for cnt_i in range(int(len(list_pt) / 8)):
        buf = [list_pt[cnt_j + int_index] for cnt_j in range(8)]
        int_index += 8
        
        list_iv = hex2list(int_iv)
        int_iv = list2hex(buf)
        buf = list2hex(buf)

        int_dst = pipo_128_dec(buf,int_key)
        list_tmp = hex2list(int_dst)

        for cnt_j in range(8):
            list_tmp[cnt_j] ^= list_iv[cnt_j]

        list_ct += list_tmp
    return list_ct

if __name__ == '__main__':

    int_iv = secrets.randbits(128)
    int_key = secrets.randbits(128)
    list_pt = [0 for cnt_i in range(16)]
    list_pt = [15,31,35,135,46,36,46,34,47,23,26,26,7,34]
    # seq="abcdefghabc"

    # list_ct = pipo_ctr_enc(list_pt,int_iv,int_key)
    # list_re = pipo_ctr_dec(list_ct,int_iv,int_key)
    # list_ct = pipo_ecb_enc(list_pt, int_key)
    # list_re = pipo_ecb_dec(list_ct, int_key)
    list_ct = pipo_cbc_enc(list_pt,int_iv,int_key)
    list_re = pipo_cbc_dec(list_ct,int_iv,int_key)
    print("IV : ", hex(int_iv))
    print("KY : ", hex(int_key))
    print("PT : ", list_pt)
    print("CT : ", list_ct)
    print("RT : ", list_re)
    # hello = hex2list(test_vecot)
    # print(hello)