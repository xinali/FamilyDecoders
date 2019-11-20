# encoding:utf-8

from idaapi import *
from idc import *
from idautils import *
from struct import unpack, pack

"""
winsoft 家族解密 by xina1i

整体流程: 
1. 定位加密函数位置
2. 获取所有加密数据位置
3. 利用加密函数解密

该版本中，加密数据位置没有直接给出，需要用 基址+固定的偏移，数据的起始位置需要解密得出

解密完大概是这样的
=================
position: 0x4298b7L ===> Software\%s
position: 0x42990cL ===> DC
position: 0x429941L ===> winsoft%d.com
position: 0x42998eL ===> http://app2.%s/app.asp?prj=%s&pid=%s&logdata=MacTryCnt:%d&code=%s&ver=%s&appcheck=1
position: 0x429b04L ===> 1
position: 0x429b25L ===> %d
position: 0x429b8bL ===> DC
position: 0x429b3eL ===> Software
position: 0x429bb5L ===> http://p2.%s/receive/r_autoidcnt.asp?mer_seq=%s&realid=%s&cnt_type=e1&mac=%s
position: 0x429d23L ===> nobundle
position: 0x429d68L ===> http://app2.%s/setup_b.asp?prj=%s&pid=%s&mac=%s
=================


部分参考md5:
4a9836e07dfe74732dbeb6a096fc55e1
"""


# 预先指定的key (样本不同，值可能不同)
specified_key = 0x16


def palevo_decode(position=None):
    """
    key     ==>  data[1]
    size    ==>  specified_key ^ data[0] 
    data    ==>  data[key ^ specified_key:]
    """
    if position:
        size = unpack("<L", GetManyBytes(position, 4))[0]
        key = unpack("<L", GetManyBytes(position+4, 4))[0] 
        start_index = (key ^ specified_key) + 2 # 数据起始位置
        size = (size ^ specified_key) & 0xff

        decode_data = []
        for i in range(size):
            data = unpack("<L", GetManyBytes(position+(i+start_index)*4, 4))[0] ^ specified_key
            data = data & 0xff # 固定范围
            decode_data.append(chr(data))
        print "position: {} ===> {}".format(hex(position), ''.join(decode_data))


def get_position():
    encode_positions = []

    # 加密函数位置
    decode_function = 0x401370
    # 数据基址
    data_base_addr = 0x4293D0

    xrefs = list(XrefsTo(decode_function))
    for i, xref in enumerate(xrefs):
        funcStart = get_func_attr(xref.frm, FUNCATTR_START)
        if funcStart == BADADDR:
            continue
        if print_insn_mnem(xref.frm) not in ["call", "jmp", "BL", "BLX", "B", "BLR"]:
            continue

        pre = PrevHead(xref.frm)
        # 定位push前的lea指令
        pre = PrevHead(pre)
        # 取得lea指令第二个操作数作为固定偏移
        value = GetOperandValue(pre, 1) 
        encode_positions.append(data_base_addr + value)
    
    return encode_positions


def main():
    encode_positions = get_position()
    
    for pos in encode_positions:
        palevo_decode(pos)

    
if __name__ == "__main__":
    main()
