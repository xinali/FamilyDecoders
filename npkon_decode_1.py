#encoding:utf-8 

from __future__ import print_function
import flare_emu


"""
Npkon.R18258 (Engine: AhnLab-V3) 家族解密 by xina1i

两个加密函数: sub_40103C sub_401046

sub_40103C: 解密使用的动态库及其使用的函数等数据
sub_401046: 解密c2等数据

方法: 如果重写两个解密函数，相对比较费时费力，直接使用flare_emu，动态模拟两个解密函数，完美解密所有需要的数据

解密完大概是这样的
######################################
===================== First Decrypt Method =======================
00404E5B: regedit.exe
00404FDF: JavaUpdate23
00405009: Update23
00404BFB:  .exe
00403AFC: ProgramFiles
00403826: advapi32.dll
0040387D: RegCreateKeyExA
004038B5: RegCloseKey
004038ED: RegDeleteValueA
00403500: advapi32.dll
00403557: RegOpenKeyExA
0040358F: RegSetValueExA
004035C7: RegCloseKey
00403618: El:b:*ad:ne
00403630: 
00403381: shell32.dll
004033C6: ShellExecuteA
004033FD: open
004030A4: wininet.dll
004030E9: InternetOpenA
00403118: InternetConnectA
00403147: FtpPutFileA
00403239: InternetCloseHandle
00402DB4: wininet.dll
00402DF9: InternetOpenA
00402E28: InternetConnectA
00402E57: FtpGetFileA
00402F4D: InternetCloseHandle
00402583: FindFirstFileA
004025B5: FindNextFileA
004025E7: FindClose
00402619: RemoveDirectoryA
0040264B: DeleteFileA
0040267D: GetDriveTypeA
004026AF: GetLogicalDriveStringsA
004026E1: CreateToolhelp32Snapshot
00402713: GetCurrentProcessId
00402745: Process32First
00402777: Process32Next
004027A9: CloseHandle
004027DB: CreateFileA
0040280D: WriteFile
0040283F: ReadFile
00402871: GetFileSize
004028A3: GlobalAlloc
004028D5: GlobalFree
00402253: kernel32.dll
0040227E: GetProcAddress
004022B9: GetModuleHandleA
004022EB: LoadLibraryA
0040231D: FreeLibrary
0040234F: SetFileAttributesA
00402381: CreateDirectoryA
004023B3: GetModuleFileNameA
004023E5: GetEnvironmentVariableA
00402417: CopyFileA
00402449: GetWindowsDirectoryA
0040247B: GetVolumeInformationA
===================== Second Decrypt Method =======================
0040541B: ProgramFiles
0040562C: ftp.byethost12.com
00405640: b12_8082975
00405654: 951753zx
00405668: griptoloji.host-ed.net
0040567C: 554591
00405690: 741852
004056A4: ftp.tripod.com
004056B8: onthelinux
004056CC: 741852abc
00405C0D: .exe
00405ED8: .exe
00405378: .exe
00404F25: Software.11111111111111111.CurrentVersion.Run
00403680: SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List
###########################################################


样本md5: 91980ba5e66d5615e45ab7733af62800 
"""

def decrypt(argv):
    myEH = flare_emu.EmuHelper()
    all_mem = myEH.allocEmuMem(100)

    # 三个参数
    myEH.emulateRange(myEH.analysisHelper.getNameAddr("sub_40103C"), stack=[0, argv[0], argv[1], argv[2]])
    return myEH.getEmuString(argv[0])
    
def iterateCallback(eh, address, argv, userData):
    s = decrypt(argv)
    print("%s: %s" % (eh.hexString(address), s))
    eh.analysisHelper.setComment(address, s, False)


def decrypt2(argv):
    myEH = flare_emu.EmuHelper()
    # 两个参数
    myEH.emulateRange(myEH.analysisHelper.getNameAddr("sub_401046"), stack=[0, argv[0], argv[1]])
    return myEH.getEmuString(argv[0])
    
def iterateCallback2(eh, address, argv, userData):
    s = decrypt2(argv)
    print("%s: %s" % (eh.hexString(address), s))
    eh.analysisHelper.setComment(address, s, False)
    
if __name__ == '__main__':
    print("===================== First Decrypt Method =======================")
    eh = flare_emu.EmuHelper()
    eh.iterate(eh.analysisHelper.getNameAddr("sub_40103C"), iterateCallback)
    print("===================== Second Decrypt Method =======================")
    eh.iterate(eh.analysisHelper.getNameAddr("sub_401046"), iterateCallback2)