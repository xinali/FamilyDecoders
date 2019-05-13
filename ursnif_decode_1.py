#encoding:utf-8 

from idaapi import *
from idc import *
from idautils import *

import struct
import sys


"""
ursnif 家族解密脚本     by xina1i

数据经过加密和压缩，解密反过来即可
解密出的数据为一个"PE文件"，写入文件使用010 editor查看即可

lznt1解密算法: 
https://github.com/you0708/lznt1/blob/bb4432f3f25c5b7549c4621fddca9672fc37c5f9/lznt1.py

样本md5:
36D032F69999FD7148D10DBB689235AC
"""

def _decompress_chunk(chunk):
    size = len(chunk)
    out = ''
    pow2 = 0x10
    while chunk:
        flags = ord(chunk[0])
        chunk = chunk[1:]
        for i in range(8):
            out_start = len(out)
            if not (flags >> i & 1):
                out += chunk[0]
                chunk = chunk[1:]
            else:
                flag = struct.unpack('<H', chunk[:2])[0]
                pos = len(out) - 1
                l_mask = 0xFFF
                o_shift = 12
                while pos >= 0x10:
                    l_mask >>= 1
                    o_shift -= 1
                    pos >>= 1

                length = (flag & l_mask) + 3
                offset = (flag >> o_shift) + 1

                if length >= offset:
                    tmp = out[-offset:] * (0xFFF / len(out[-offset:]) + 1)
                    out += tmp[:length]
                else:
                    out += out[-offset:-offset+length]
                chunk = chunk[2:]
            if len(chunk) == 0:
                break
    return out

# 解压缩
def decompress(buf, length_check=True):
    out = ''
    while buf:
        header = struct.unpack('<H', buf[:2])[0]
        length = (header & 0xFFF) + 1
        if length_check and length > len(buf[2:]):
            raise ValueError('invalid chunk length')
        else:
            chunk = buf[2:2+length]
            if header & 0x8000:
                out += _decompress_chunk(chunk)
            else:
                out += chunk
        buf = buf[2+length:]
    return out


# 解密出未解压数据
def decode_compress_data():
    fp = open('036D.log', 'wb')
    ea = 0x43AC10
    store_data = ''
    for i in range(0, 0x973):
        pos_1 = ea + 24 * i  + 4
        v71 = GetManyBytes(pos_1, 4)
        data_2_address = struct.unpack("<L", v71)[0]
    
        pos_2 = ea + i * 24 + 12
        v4 = GetManyBytes(pos_2, 2)
        index = struct.unpack("<H", v4)[0]
    
        print 'index:', index
    
        for j in range(0, index):
            data_1_address = 0x42CD40
            data_1_str = GetManyBytes(data_1_address + j % 0xD + 2, 1)
            data_1 = struct.unpack("<B", data_1_str)[0]
            
            data_2_str = GetManyBytes(data_2_address + j, 1)
            data_2 = struct.unpack("<B", data_2_str)[0]
            final_data = data_2 - data_1
            fp.write(struct.pack("B", final_data & 0xff))
    fp.close()    


def main():
    decode_compress_data()
    fp = open('036D.log', 'rb')
    data = fp.read()
    fp.close()
    decompress_data = decompress(data, len(data))
    fp = open('decompress.log', 'wb')
    print decompress_data[:20]
    fp.write(decompress_data)
    fp.close()

if __name__ == "__main__":
    main()
