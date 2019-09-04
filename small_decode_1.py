# encoding: utf-8


"""

small 家族解密  by xina1i

该家族该版本目前存在的主要形式是upx壳，脱完壳可以使用该脚本解密

未脱壳样本ma5：4b903163688b2dc71d5dd29eda993854

可以利用upx直接脱
upx.exe -d 4b903163688b2dc71d5dd29eda993854 -o unpack_sample

脱完壳样本md5: 54ab913d71d14fff92b67af4f44b904b


样本所有配置信息包括c2均使用sub_4112C0解密，直接定位到函数并获取函数参数，解密即可

解密完大概这样

=============== Decode Small Family ===============
[-] encode_string: cftcrk10,fnn ===> length: 12
[+] 0x4108ecL =decode=> advapi32.dll 
[-] encode_string: igplgn10,fnn ===> length: 12
[+] 0x4108fcL =decode=> kernel32.dll 
[-] encode_string: EgvRpmaCffpgqq ===> length: 14
[+] 0x41090cL =decode=> GetProcAddress 
[-] encode_string: EgvGltkpmloglvTcpkc`ngC ===> length: 23
[+] 0x41091cL =decode=> GetEnvironmentVariableA 
[-] encode_string: UklGzga ===> length: 7
[+] 0x410934L =decode=> WinExec 
[-] encode_string: Amr{DkngC ===> length: 9
[+] 0x41093cL =decode=> CopyFileA 
[-] encode_string: QgvDkngCvvpk`wvgqC ===> length: 18
[+] 0x410948L =decode=> SetFileAttributesA 
[-] encode_string: PgeQgvTcnwgGzC ===> length: 14
[+] 0x41095cL =decode=> RegSetValueExA 
[-] encode_string: PgeAnmqgIg{ ===> length: 11
[+] 0x41096cL =decode=> RegCloseKey 
[-] encode_string: PgeMrglIg{C ===> length: 11
[+] 0x410978L =decode=> RegOpenKeyA 
[-] encode_string: jvvr8--3;7,;1,03:,07-nf- ===> length: 24
[+] 0x410984L =decode=> http://195.93.218.25/ld/ 
[-] encode_string: jvvr8--js/rjcpoc,mpe- ===> length: 21
[+] 0x4109a8L =decode=> http://hq-pharma.org/ 
[-] encode_string: advoml,gzg ===> length: 10
[+] 0x4109c0L =decode=> cftmon.exe 
[-] encode_string: qrmmnq,gzg ===> length: 10
[+] 0x4109ccL =decode=> spools.exe 
[-] encode_string: dvrfnn,fnn ===> length: 10
[+] 0x4109d8L =decode=> ftpdll.dll 
[-] encode_string: lvfnn,fnn ===> length: 9
[+] 0x4109e4L =decode=> ntdll.dll 
[-] encode_string: LvSwgp{Q{qvgoKldmpocvkml ===> length: 24
[+] 0x4109f0L =decode=> NtQuerySystemInformation 
[-] encode_string: LvNmcfFpktgp ===> length: 12
[+] 0x410a0cL =decode=> NtLoadDriver 
[-] encode_string: PvnKlkvWlkamfgQvpkle ===> length: 20
[+] 0x410a1cL =decode=> RtlInitUnicodeString 
[-] encode_string: IgQgptkagFgqapkrvmpVc`ng ===> length: 24
[+] 0x410a80L =decode=> KeServiceDescriptorTable 
[-] encode_string: Qmdvucpg^Okapmqmdv^Uklfmuq^AwppglvTgpqkml^Pwl^ ===> length: 46
[+] 0x410ba8L =decode=> Software\Microsoft\Windows\CurrentVersion\Run\ 
[-] encode_string: Q[QVGO^AwppglvAmlvpmnQgv^Qgptkagq^Qajgfwng ===> length: 42
[+] 0x410be4L =decode=> SYSTEM\CurrentControlSet\Services\Schedule 
[-] encode_string: Q{qvgoFpktg ===> length: 11
[+] 0x410c44L =decode=> SystemDrive 
[-] encode_string: AMOPWVGPLCOG ===> length: 12
[+] 0x410cb0L =decode=> COMRUTERNAME 
[-] encode_string: uklfkp ===> length: 6
[+] 0x410cc0L =decode=> windir 
[-] encode_string: ^q{qvgo10 ===> length: 9
[+] 0x410cc8L =decode=> \system32 
[-] encode_string: WQGPRPMDKNG ===> length: 11
[+] 0x410cd4L =decode=> USERPROFILE 
[-] encode_string: ^Nmacn"Qgvvkleq^Crrnkacvkml"Fcvc ===> length: 32
[+] 0x410ce0L =decode=> \Local Settings\Application Data 
[-] encode_string: ^fpktgpq^ ===> length: 9
[+] 0x410d04L =decode=> \drivers\ 
[-] encode_string: ^Nmacn"Qgvvkleq^Crrnkacvkml"Fcvc^ ===> length: 33
[+] 0x410d10L =decode=> \Local Settings\Application Data\ 
[-] encode_string: ^fpktgpq^ ===> length: 9
[+] 0x410d40L =decode=> \drivers\ 
[-] encode_string: q{qrpma,q{q ===> length: 11
[+] 0x410d4cL =decode=> sysproc.sys 
[-] encode_string: uklklgv,fnn ===> length: 11
[+] 0x410a34L =decode=> wininet.dll 
[-] encode_string: KlvgplgvMrglC ===> length: 13
[+] 0x410a40L =decode=> InternetOpenA 
[-] encode_string: KlvgplgvMrglWpnC ===> length: 16
[+] 0x410a50L =decode=> InternetOpenUrlA 
[-] encode_string: KlvgplgvPgcfDkng ===> length: 16
[+] 0x410a64L =decode=> InternetReadFile 
[-] encode_string: Amlvglv/V{rg8"crrnkacvkml-z/uuu/dmpo/wpnglamfgf ===> length: 47
[+] 0x410d88L =decode=> Content-Type: application/x-www-form-urlencoded 

"""


from idaapi import *
from idc import *
from idautils import *


def get_string(addr):
    out = ""
    while True:
        if Byte(addr) != 0:
            out += chr(Byte(addr))
        else:
            break
        addr += 1
    return out


def decode(str_encode_positions=None):
    if str_encode_positions:
        for str_encode_position in str_encode_positions:
            str_encode = ''
            str_decode = ''

            str_encode = get_string(str_encode_position)
            print("[-] encode_string: {en_data} ===> length: {data_len}".format(en_data=str_encode, data_len=len(str_encode)))
            for i in range(len(str_encode)):
                str_decode += chr(ord(str_encode[i]) ^ 2)

            print("[+] {pos} =decode=> {de} ".format(pos=hex(str_encode_position), de=str_decode))


def get_position(xref_func_position=None):
    if xref_func_position:
        encode_positions = []
        xrefs = list(XrefsTo(xref_func_position))
        
        for i, xref in enumerate(xrefs):
            funcStart = get_func_attr(xref.frm, FUNCATTR_START)
            if funcStart == BADADDR:
                continue
            if print_insn_mnem(xref.frm) not in ["call", "jmp", "BL", "BLX", "B", "BLR"]:
                continue

            pre_asm = PrevHead(xref.frm)
            encode_position = GetOperandValue(pre_asm, 0) 
            encode_positions.append(encode_position)
        
        return encode_positions
    return None


if __name__ == '__main__':
    print "=============== Decode Small Family ==============="
    xref_func_position = 0x4112C0
    encode_positions = get_position(xref_func_position)
    decode(encode_positions)