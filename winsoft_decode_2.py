# encoding:utf-8

from idaapi import *
from idc import *
from idautils import *
from struct import unpack, pack

"""
winsoft 家族解密 by xina1i

存在大量无用的混淆代码，分析时需要注意主要解密语句
该家族的这个版本的解密方法，都是通过加密数据直接+/-/^一个key解密

其中key的规律我还没有发现


解密完大概是这样的
=================
55                                      push    ebp
8B EC                                   mov     ebp, esp
83 C4 88                                add     esp, 0FFFFFF88h
C7 45 D8 9C 36 00 00                    mov     dword ptr [ebp-28h], 369Ch
C7 45 D4 00 00 00 00                    mov     dword ptr [ebp-2Ch], 0
C7 45 D0 A0 65 00 00                    mov     dword ptr [ebp-30h], 65A0h
C7 45 CC 00 1A 01 00                    mov     dword ptr [ebp-34h], 11A00h
C7 45 C8 A0 7F 01 00                    mov     dword ptr [ebp-38h], 17FA0h
C7 45 C4 00 1A 01 00                    mov     dword ptr [ebp-3Ch], 11A00h
...
=================

其通过fs:30，利用peb中的ldr链导入函数，之后进行恶意行为

样本md5: 5e4d17c6b863cf6984c66e95b7b6afad
"""

from idaapi import *
from idc import *
from idautils import *
from struct import unpack, pack

def palevo_decode(position=None):
    position = 0x4180a0
    shellcode = ''
    if position:
        for i in range(0x26D):
            data = unpack("<L", GetManyBytes(position+4*i, 4))[0] 
            decode_data = (data - 0xA1B3B8EF) & 0xffffffff
            shellcode += pack("<L", decode_data)
    
    with open('shellcode_palevo.bin', 'wb') as fp:
        fp.write(shellcode)
        fp.close()
    

if __name__ == "__main__":
    palevo_decode()