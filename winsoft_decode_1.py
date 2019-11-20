# encoding:utf-8

from idaapi import *
from idc import *
from idautils import *
from struct import unpack, pack

"""
winsoft 家族解密 by xina1i

目前该家族有部分是未加密直接使用c2或者关键数据的，还有相当大一部分是使用该加解密方法

整体流程: 
1. 定位加密函数位置
2. 获取所有加密数据位置
3. 利用加密函数解密

解密完大概是这样的
=================
position: 0x4116f8L ===> http://p2.winsoft1.com/receive/r_autoidcnt.asp?mer_seq=%s&realid=%s&cnt_type=l&mac=%s
position: 0x411b24L ===> update
position: 0x4116dcL ===> Code
position: 0x4122e0L ===> Software
position: 0x4116dcL ===> Code
position: 0x4122e0L ===> Software
position: 0x411578L ===> http://p2.winsoft1.com/receive/r_autoidcnt.asp?mer_seq=%s&realid=%s&cnt_type=e8&mac=%s
=================


部分参考md5:
f13dbd6f5b820adee9ab105ad6c56a47
13835bc87110a3e52c06fa79cd27e0b5
"""

def palevo_decode(position=None):
    """
    key     ==>  data[1]
    size    ==>  key ^ data[0] 
    data    ==>  data[2:]
    """
    if position:
        key = unpack("<L", GetManyBytes(position+4, 4))[0] 
        data_length = unpack("<L", GetManyBytes(position, 4))[0] ^ key
        start_index = 2

        decode_data = []
        for i in range(data_length):
            data = unpack("<L", GetManyBytes(position+(i+start_index)*4, 4))[0] ^ key
            decode_data.append(chr(data))
        print "position: {} ===> {}".format(hex(position), ''.join(decode_data))


def get_position():
    encode_positions = []

    # 加密函数位置
    decode_function = 0x401cf0
    xrefs = list(XrefsTo(decode_function))
    for i, xref in enumerate(xrefs):
        funcStart = get_func_attr(xref.frm, FUNCATTR_START)
        if funcStart == BADADDR:
            continue
        if print_insn_mnem(xref.frm) not in ["call", "jmp", "BL", "BLX", "B", "BLR"]:
            continue

        pre = PrevHead(xref.frm)
        value = GetOperandValue(pre, 0) 
        encode_positions.append(value)
    
    return encode_positions


def main():
    encode_positions = get_position()
    # network function
    # encode_positions = [0x413274, 0x41329C, 0x413340, 0x4132AC, 0x4132C0, 0x413354, 0x4133D0, 0x413418]

    # before network function
    # encode_positions = [0x4138D0, 0x413A18, 0x4136F8, 0x4143E8, 0x414558, 0x4136A4, 0x413648, 0x413AE0]

    for pos in encode_positions:
        palevo_decode(pos)

    
if __name__ == "__main__":
    main()
