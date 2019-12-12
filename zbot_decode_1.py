#encoding:utf-8 


"""
zbot 家族解密  by xina1i

调用RtlDecompressBuffer => lznt1(python)

样本hash:
c9e91a3f8b994d33ab548ef4b688a2f870339c89f8dcc1455e862282ebd57a70

"""
from idaapi import *
from idc import *
from idautils import *

import struct
import sys


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

# è§£åŽ‹ç¼©
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


def main():
    ea = 0x404000
    data = GetManyBytes(ea, 0x100)
    decompress_data = decompress(data, len(data))
    print len(decompress_data)
    fp = open('decompress_data.bin', 'wb')
    fp.write(decompress_data)
    fp.close()
    print decompress_data.split('\x00')


if __name__ == "__main__":
    main()
