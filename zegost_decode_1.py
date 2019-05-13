#encoding:utf-8 

from idaapi import *
from idc import *
from idautils import *

"""
zegost 家族解密 by xina1i
解密函数解密了两个部分，这里测试了其中一个跟c2有关的位置

解密出的c2:
ma.owwwv.com/m.owwwv.com

样本md5:
4d3358c407c93b8a2b2e10297d64fc00
"""

ea = 0x409078
encode_data = GetManyBytes(ea, 0x19a)
encode_data_list = list(encode_data)
key_array = [0x4d, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x33, 0x36, 0x30, 0] # Mother360

a1_array = [x for x in xrange(0,256)]

def decode_func1():
    global a1_array
    global key_array

    index_v6 = 0
    tmp_array = [x for x in xrange(0, 256)]

    for index_v4 in xrange(0, 256):
        index_v6 = index_v4 % 10
        a1_array[index_v4] = index_v4
        tmp_array[index_v4] = key_array[index_v6]

    v14 = 0    
    for array_index in xrange(0, 256):
        v7 = tmp_array[array_index]
        v8 = a1_array[array_index]
        v9 = v14 + v7 + v8
        v10 = v9 % 256
        result = a1_array[v10]
        v14 = v10
        a1_array[array_index] = result
        a1_array[v10] = v8


def decode_func2():
    global a1_array
    global encode_data

    index_len = 0x19a
    result = 0
    v7 = 0
    index = 0
    while True:
        v5 = (result + 1) % 256
        v6 = a1_array[v5]
        v7 = (v7 + v6) % 256
        a1_array[v5] = a1_array[v7]
        a1_array[v7] = v6

        tmp_data = a1_array[(a1_array[v5]+v6) % 256] & 0xff
        encode_data_list[index] = ord(encode_data_list[index]) & 0xff ^ tmp_data
        index += 1
        if index >= index_len:
            break
        result = v5
    
    for i in xrange(0, 256):
        if chr(encode_data_list[i]) != ' ':
            print chr(encode_data_list[i]),

if __name__ == '__main__':
    decode_func1()
    decode_func2()      
