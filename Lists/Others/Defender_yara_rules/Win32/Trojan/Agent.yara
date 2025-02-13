rule Trojan_Win32_Agent_N_2147512730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.N"
        threat_id = "2147512730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 f8 82 40 00 64 8b 15 30 00 00 00 8b 42 0c 8b 70 1c 8b 16 8b 42 08 a3 2c 85 40 00 a1 1c 83 40 00 8d 05 1c 83 40 00 50 c3 a1 2c 85 40 00 85 c0 75 09}  //weight: 1, accuracy: High
        $x_1_2 = {8b 70 1c 8b 16 8b 42 08 a3 2c 85 40 00 a1 1c 83 40 00 8d 05 1c 83 40 00 50 c3 a1 2c 85 40 00 85 c0 75 09 33 c0 5e 8b e5 5d c2 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Agent_BM_2147514210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.BM"
        threat_id = "2147514210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_2 = "unpacked\\" ascii //weight: 1
        $x_1_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 00 00 ff ff ff ff 04 00 00 00 4d 59 49 44}  //weight: 1, accuracy: High
        $x_1_4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 1
        $x_1_5 = "svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_6 = "Referer: http://" ascii //weight: 1
        $x_1_7 = "capCreateCaptureWindowA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Agent_CY_2147550460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.CY"
        threat_id = "2147550460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 84 24 07 03 00 00 61 c6 84 24 08 03 00 00 e9 88 9c 24 09 03 00 00 88 9c 24 0a 03 00 00 88 9c 24 0b 03 00 00 88 9c 24 0c 03 00 00 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {eb 03 8d 49 00 0f b7 01 66 89 02 83 c1 02 83 c2 02 66 85 c0 75 ef b8}  //weight: 2, accuracy: High
        $x_1_3 = "\\\\.\\pipe\\NannedPipe" wide //weight: 1
        $x_1_4 = "Iprip" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" wide //weight: 1
        $x_1_6 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_2147567314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent"
        threat_id = "2147567314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IEHpr.DLL" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = {00 31 2e 74 78 74}  //weight: 1, accuracy: High
        $x_1_4 = {00 31 2e 62 6d 70}  //weight: 1, accuracy: High
        $x_1_5 = {00 31 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_6 = {00 31 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_7 = "OpenServiceA" ascii //weight: 1
        $x_1_8 = "OpenSCManagerA" ascii //weight: 1
        $x_1_9 = "OpenMutexA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_2147567314_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent"
        threat_id = "2147567314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "116.122.135.13/access_count.html" ascii //weight: 1
        $x_1_3 = "deleteself.bat" ascii //weight: 1
        $x_1_4 = "Execute_Updater" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "DownloadRandomUrlFile" ascii //weight: 1
        $x_1_7 = "InternetOpenA" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_2147567314_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent"
        threat_id = "2147567314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "c:\\windows\\systemp.exe" ascii //weight: 10
        $x_1_2 = "c:\\wabok.log" ascii //weight: 1
        $x_1_3 = "c:\\nois.log" ascii //weight: 1
        $x_1_4 = "email=" ascii //weight: 1
        $x_1_5 = "computador=" ascii //weight: 1
        $x_1_6 = "nomfile=" ascii //weight: 1
        $x_1_7 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_2147567314_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent"
        threat_id = "2147567314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {4f 4b 00 00 66 75 63 6b 20 4e 4f 44 33 32 20 74 77 6f 20 74 69 6d 65 73 00 00 00 00 45 52 52 4f 52 00 00 00 66 75 63 6b 20 4e 4f 44 33 32 20 66 69 72 73 74 20 74 69 6d 65 73}  //weight: 3, accuracy: High
        $x_1_2 = "2killyouall" ascii //weight: 1
        $x_1_3 = "Server to Client" ascii //weight: 1
        $x_1_4 = "Client to Server" ascii //weight: 1
        $x_1_5 = {89 5c 24 1c e8 92 12 00 00 bf ?? ?? ?? ?? 83 c9 ff 33 c0 f2 ae f7 d1 49 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 09 0c 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_2147567314_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent"
        threat_id = "2147567314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 50 40 00 38 50 40 00 53 74 61 72 74 00 00 00 5c 64 6f 6e 6d 2e 64 6c 6c 00 00 00 57 69 6e 73 74 61 30 5c 44 65 66 61 75 6c 74 00 20 20 2a 00 20 20 00 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 00 00 00 6a 70 67 00 9d 15 40 00 02 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 88 13 00 00 c7 44 24 ?? 01 00 00 00 c7 44 24 ?? ?? ?? ?? 00 66 89 44 24 ?? ff 15 ?? ?? ?? 00 8d 44 24 ?? 8d 4c 24 ?? 50 51 6a 00 6a 00 6a 00 6a 01 6a 00 6a 00 68 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? 00 5f 33 c0 5e 83 c4 ?? c2 10 00}  //weight: 1, accuracy: Low
        $x_1_3 = "rundll32.exe C:\\WINDOWS\\SYSTEM32\\donm.dll  Start  *" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Agent_2147567314_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent"
        threat_id = "2147567314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "spider.gucciservice.biz" ascii //weight: 10
        $x_10_2 = "\\wbstore.dll" ascii //weight: 10
        $x_1_3 = "/data.php?user=" ascii //weight: 1
        $x_1_4 = "&pass=" ascii //weight: 1
        $x_1_5 = "&domain=" ascii //weight: 1
        $x_1_6 = "&locip=" ascii //weight: 1
        $x_1_7 = "&cpuname=" ascii //weight: 1
        $x_1_8 = "USER:" ascii //weight: 1
        $x_1_9 = "PASS:" ascii //weight: 1
        $x_1_10 = "DOMEN:" ascii //weight: 1
        $x_1_11 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_12 = "HttpSendRequest" ascii //weight: 1
        $x_1_13 = "InternetConnectA" ascii //weight: 1
        $x_1_14 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_2147567314_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent"
        threat_id = "2147567314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "95"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "QQSG.exe" ascii //weight: 10
        $x_10_2 = "hook" ascii //weight: 10
        $x_10_3 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_4 = "CreateRemoteThread" ascii //weight: 10
        $x_10_5 = "WriteProcessMemory" ascii //weight: 10
        $x_10_6 = "SetWindowsHookExA" ascii //weight: 10
        $x_10_7 = "InternetOpenUrlA" ascii //weight: 10
        $x_10_8 = "strrchr" ascii //weight: 10
        $x_10_9 = "C:\\WINDOWS\\SYSTEM32\\TesSafe.sys" ascii //weight: 10
        $x_1_10 = "http://127.0.0.1/lin.asp" ascii //weight: 1
        $x_1_11 = "D:\\HaHa5.0\\Housr\\DUMMYSYS\\objfre_wnet_x86\\i386\\TesSafe.pdb" ascii //weight: 1
        $x_1_12 = "SGMUTEX" ascii //weight: 1
        $x_1_13 = "World" ascii //weight: 1
        $x_1_14 = "Zone.ini" ascii //weight: 1
        $x_1_15 = "ntoskrnl.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_S_2147582668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.S"
        threat_id = "2147582668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {62 62 6d 65 65 6f 6d 6e 76 70 6f 70 2e 64 6c 6c 00 42 70 6f 64 6d 73 73 65 6c 69 6f 63 44 66 72 74 6f 6f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_AAC_2147584418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AAC"
        threat_id = "2147584418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Goto SuperrSoft.com.URL" ascii //weight: 10
        $x_1_2 = "360safe" ascii //weight: 1
        $x_1_3 = "wopticlean" ascii //weight: 1
        $x_1_4 = "qq.exe" ascii //weight: 1
        $x_1_5 = "rundll32.exe" ascii //weight: 1
        $x_1_6 = "taskmgr.exe" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "SeShutdownPrivilege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_ACC_2147592560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ACC"
        threat_id = "2147592560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "213"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_10_2 = "CreateStreamOnHGlobal" ascii //weight: 10
        $x_10_3 = "ImageList_SetIconSize" ascii //weight: 10
        $x_10_4 = "InternetGetConnectedState" ascii //weight: 10
        $x_10_5 = "timeGetTime" ascii //weight: 10
        $x_10_6 = {73 68 75 74 64 6f 77 6e 00}  //weight: 10, accuracy: High
        $x_10_7 = {73 6f 63 6b 65 74 00}  //weight: 10, accuracy: High
        $x_10_8 = "TIdEMailAddressList" ascii //weight: 10
        $x_10_9 = "TIdIOHandlerSocket" ascii //weight: 10
        $x_10_10 = "RemoteMachineName" ascii //weight: 10
        $x_10_11 = "WinExec" ascii //weight: 10
        $x_10_12 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4c 00 54 00 61 00 73 00 6b 00 75 00 70 00}  //weight: 10, accuracy: High
        $x_1_13 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: High
        $x_1_14 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_15 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_16 = {4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 11 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_RX_2147593299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.RX"
        threat_id = "2147593299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "rundll32.exe C:\\WINDOWS\\SYSTEM32\\ntoskrnl.dll , DllMain" ascii //weight: 100
        $x_100_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 69 76 65 72 73 5c 69 6e 65 74 78 ?? ?? ?? 2e 69 6d 67}  //weight: 100, accuracy: Low
        $x_100_3 = "winsta0\\default" ascii //weight: 100
        $x_100_4 = {4f 46 54 57 41 52 45 5c 4d 69 63 1d f6 2f 6f 35 73 6f 66 57 69 6e 64 6f 77 73 4f 56 eb b6 cd df 2f 69 6f 6e 5c 52 75 6e 5c 64 48 76 11 5c 0b 36 b0 ff db 1c 73 79 73 74 65 6d 2e 65 78 65 1b 40 b1 f2 dd b7 7c 78 2a 2e 2a 23 73 76 63 68 6f 21 fd b7 d6 66 a7 13 36 11 6b 72 6e 6c 2e 64 6c 6c}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Agent_ADA_2147593985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ADA"
        threat_id = "2147593985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 52 4c 4d 4f 4e 2e 64 6c 6c 00 44 6f 57 6f 72 6b 00 49 6e 73 74 61 6c 6c 00 52 75 6e 4f 6e 63 65 00 55 6e 69 6e 73 74 61 6c 6c 00 57 53 50 53 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
        $x_1_2 = "iv=%ld&pv=%ld&lg=%s&co=%s&c=%ld&f=%s&i=%ld&sc=%ld&sl=%ld" ascii //weight: 1
        $x_1_3 = "ipconfig /renew" ascii //weight: 1
        $x_1_4 = "Layered WS2 Provider" wide //weight: 1
        $x_1_5 = "Layered Hidden Window" wide //weight: 1
        $x_1_6 = "urldownloadtofilea" ascii //weight: 1
        $x_1_7 = "VideoBiosDate" ascii //weight: 1
        $x_1_8 = "SystemBiosDate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_ADF_2147594061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ADF"
        threat_id = "2147594061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%system%\\debitos.scr" ascii //weight: 1
        $x_1_2 = "%system%\\my_backdoor (no x win 2000).exe" ascii //weight: 1
        $x_1_3 = "%system%\\eexplorer.exe" ascii //weight: 1
        $x_1_4 = "%system%\\keyhook.dll" ascii //weight: 1
        $x_1_5 = "%windir%\\help\\kill.exe" ascii //weight: 1
        $x_1_6 = "%desktop%\\Backdoor.IRC.Cloner.v.exe" ascii //weight: 1
        $x_1_7 = "%desktop%\\Backdoor.IRC.Bnc.c.exe" ascii //weight: 1
        $x_1_8 = "%desktop%\\Backdoor.IRC.Belio.exe" ascii //weight: 1
        $x_1_9 = "%desktop%\\Backdoor.IRC.Banned.b.exe" ascii //weight: 1
        $x_1_10 = "%desktop%\\Backdoor.IRC.Ataka.a.exe" ascii //weight: 1
        $x_1_11 = "%system%\\svcxnv32.exe" ascii //weight: 1
        $x_1_12 = "%windir%\\winsocks5.exe" ascii //weight: 1
        $x_1_13 = "%system%\\winsdata.exe" ascii //weight: 1
        $x_1_14 = "%system%\\ravmond.exe" ascii //weight: 1
        $x_1_15 = "%system%\\WINWGPX.EXE" ascii //weight: 1
        $x_1_16 = "%desktop%\\Backdoor.IRC.Acnuz.exe" ascii //weight: 1
        $x_1_17 = "%desktop%\\Backdoor.ASP.Ace.b.exe" ascii //weight: 1
        $x_1_18 = "%desktop%\\Backdoor.ASP.Ace.a.exe" ascii //weight: 1
        $x_1_19 = "%desktop%\\msn\\Backdoor.Win32.MSNCorrupt.exe.exe" ascii //weight: 1
        $x_1_20 = "%desktop%\\Backdoor.Win32.Bifrose.a.exe" ascii //weight: 1
        $x_1_21 = "%desktop%\\Auto-Keylogger-Setup.exe" ascii //weight: 1
        $x_1_22 = "%desktop%\\AuroraInfection.exe" ascii //weight: 1
        $x_1_23 = "software\\anti-lamer backdoor" ascii //weight: 1
        $x_1_24 = "my_backdoor (no x win 2000)" ascii //weight: 1
        $x_1_25 = "%windir%internat.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (13 of ($x*))
}

rule Trojan_Win32_Agent_ADF_2147594061_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ADF"
        threat_id = "2147594061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "230"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-9] 2e 65 78 65}  //weight: 100, accuracy: Low
        $x_100_2 = "www.porn.com" ascii //weight: 100
        $x_10_3 = "ShellExecute" ascii //weight: 10
        $x_10_4 = "BlockInput" ascii //weight: 10
        $x_10_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_1_6 = "Neanderthal is watching you" ascii //weight: 1
        $x_1_7 = "You can't cancel me mother fucker!" ascii //weight: 1
        $x_1_8 = "Naughty, Naughty, looking at porn are we now?... Dispicable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_IU_2147594773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.IU"
        threat_id = "2147594773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_3 = "\\Microsoft\\Internet Explorer\\Quick Launch" ascii //weight: 1
        $x_1_4 = "[InternetShortcut]" ascii //weight: 1
        $x_1_5 = "InternetReadFile" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = "Start Page" ascii //weight: 1
        $x_1_8 = "HTTPTEST" ascii //weight: 1
        $x_1_9 = "homeurl" ascii //weight: 1
        $x_1_10 = "gaptime" ascii //weight: 1
        $x_1_11 = "homedesc" ascii //weight: 1
        $x_1_12 = "iconurl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_ABK_2147595282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ABK"
        threat_id = "2147595282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fixfile.exe" ascii //weight: 1
        $x_1_2 = "Autorun.inf" ascii //weight: 1
        $x_1_3 = ":\\Autorun.inf" ascii //weight: 1
        $x_1_4 = "[AutoRun]" ascii //weight: 1
        $x_1_5 = "open=Recyc1ed\\Mcshie1d.exe" ascii //weight: 1
        $x_1_6 = "shell\\open\\Command=\"Recyc1ed\\Mcshie1d.exe" ascii //weight: 1
        $x_1_7 = "shell\\explore\\Command=\"Recyc1ed\\Mcshie1d.exe -e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Agent_AFA_2147595946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AFA"
        threat_id = "2147595946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {bf cd bb a7 b6 cb ba cd b7 fe ce f1 c6 f7 d6 ae bc e4 b5 c4 20 4e 45 54 20 53 45 4e 44 20 ba cd 20 41 6c 65 72 74 65 72 20 b7 fe ce f1 cf fb cf a2 a1 a3 b4 cb b7 fe ce f1 d3 eb 20 57 69 6e 64 6f 77 73 20 4d 65 73 73 65 6e 67 65 72 20 ce de b9 d8 a1 a3 c8 e7 b9 fb b7 fe ce f1 cd a3 d6 b9 a3 ac 41 6c 65 72 74 65 72 20 cf fb cf a2 b2 bb bb e1 b1 bb b4 ab ca e4 a1 a3 c8 e7 b9 fb b7 fe ce f1 b1 bb bd fb d3 c3 a3 ac c8 ce ba ce d6 b1 bd d3 d2 c0 c0 b5 d3 da b4 cb b7 fe ce f1 b5 c4 b7 fe ce f1 bd ab ce de b7 a8 c6 f4 b6 af a1 a3}  //weight: 10, accuracy: High
        $x_5_2 = "dos.haowan1.com" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_BB_2147596522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.BB"
        threat_id = "2147596522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\csrss.exe" ascii //weight: 1
        $x_1_2 = " if exist \"%s\" goto Repeat" ascii //weight: 1
        $x_1_3 = "InternetExplorer.Application" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3" ascii //weight: 1
        $x_1_5 = "Content-Type: application/x-www-form-urlencoded" wide //weight: 1
        $x_1_6 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_7 = " document.body.oncontextmenu=mf</script>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_OI_2147596527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.OI"
        threat_id = "2147596527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "302"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Windows Atualizado Com Sucesso" ascii //weight: 100
        $x_100_2 = "C:\\windows\\windowsupdate7.exe" ascii //weight: 100
        $x_100_3 = "http://experimental.sitesled.com/wind.jpg" ascii //weight: 100
        $x_10_4 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" ascii //weight: 10
        $x_10_5 = "uxtheme.dll" ascii //weight: 10
        $x_1_6 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_7 = "ShellExecuteA" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 2 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_OJ_2147596550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.OJ"
        threat_id = "2147596550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://superfast.com.sapo.pt/fotos.com" ascii //weight: 10
        $x_10_2 = "c:\\895004.exe" ascii //weight: 10
        $x_10_3 = "c:\\605645.txt" ascii //weight: 10
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_OL_2147596569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.OL"
        threat_id = "2147596569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "142"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {55 8b ec b9 05 00 00 00 6a 00 6a 00 49 75 f9 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 45 ec e8 ?? ?? ?? ?? 8d 45 ec ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ec b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 e8 e8 ?? ?? ?? ?? 8d 45 e8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 e8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 e4 e8 ?? ?? ?? ?? 8d 45 e4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 e4 e8 ?? ?? ?? ?? 84 c0 74 25 6a 00 8d 45 e0}  //weight: 100, accuracy: Low
        $x_20_2 = "URLDownloadToFileA" ascii //weight: 20
        $x_20_3 = "WinExec" ascii //weight: 20
        $x_2_4 = "\\rudll32.exe" ascii //weight: 2
        $x_2_5 = "\\notpad.exe" ascii //weight: 2
        $x_2_6 = "\\ashMails.exe" ascii //weight: 2
        $x_2_7 = "\\ashServs.exe" ascii //weight: 2
        $x_2_8 = "\\x000.exe" ascii //weight: 2
        $x_2_9 = "\\agentesfirewall.exe" ascii //weight: 2
        $x_2_10 = "\\plugin.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_20_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_OM_2147596570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.OM"
        threat_id = "2147596570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "115"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "78E1BDD1-9941-11cf-9756-00AA00C00908" wide //weight: 100
        $x_5_2 = "C:\\windows\\system\\sysintes.exe" wide //weight: 5
        $x_5_3 = "C:\\windows\\system\\mbda.exe" wide //weight: 5
        $x_1_4 = "RemoteHost" ascii //weight: 1
        $x_1_5 = "RemotePort" ascii //weight: 1
        $x_1_6 = "UserName" ascii //weight: 1
        $x_1_7 = "Password" ascii //weight: 1
        $x_1_8 = "FtpFindFirstFileA" ascii //weight: 1
        $x_1_9 = "InternetFindNextFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_APP_2147596923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.APP"
        threat_id = "2147596923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "dek390f0f928d92" wide //weight: 10
        $x_10_2 = "399d992ksjfhs9" ascii //weight: 10
        $x_10_3 = {5c 6e 2e 69 6e 69 00}  //weight: 10, accuracy: High
        $x_10_4 = "document.body.oncontextmenu=mf</script>" wide //weight: 10
        $x_10_5 = "function mf() { return false; }" wide //weight: 10
        $x_10_6 = "\\wbem\\csrss.exe" ascii //weight: 10
        $x_10_7 = "if exist \"%s\" goto repeat" ascii //weight: 10
        $x_10_8 = "internet settings\\zones\\3" ascii //weight: 10
        $x_10_9 = "data=%s&key=%s" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_Agent_BUI_2147596924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.BUI"
        threat_id = "2147596924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 4c 4c 53 54 41 52 54 45 52 2e 64 6c 6c 00 ?? ?? (61|2d|7a) (61|2d|7a) 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = "%08X.dll" ascii //weight: 10
        $x_1_3 = "Microsoft Corporation. All rights reserved." wide //weight: 1
        $x_10_4 = {c7 45 0c 9a 02 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_ADH_2147597186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ADH"
        threat_id = "2147597186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BASESRV.BaseSrvNlsUpdateRegistryCache" ascii //weight: 1
        $x_1_2 = "BASESRV.BaseSetProcessCreateNotify" ascii //weight: 1
        $x_1_3 = "BASESRV.ServerDllInitialization" ascii //weight: 1
        $x_1_4 = "BASESRV.BaseSrvNlsLogon" ascii //weight: 1
        $x_1_5 = "BASESRV.DLL" ascii //weight: 1
        $x_1_6 = {50 6a 07 6a 2a 68 ?? ?? ?? ?? e8 02 35 00 00 53 8d 85 d4 fd ff ff 50 8d 45 eb 50 8d 45 f4 50 e8 47 33 00 00 6a 07 8d 45 eb 50 e8 83 30 00 00 8d 45 f4 50 50 53 53 be ?? ?? ?? ?? 56 e8 e7 fc ff ff ff d0 85 c0 0f 8c 3e 02 00 00 68 ?? ?? ?? ?? 8d 45 e9 50 6a 09 6a 18 68 ?? ?? ?? ?? e8 af 34 00 00 53 8d 85 d4 fd ff ff 50 8d 45 e9 50 8d 45 f4 50 e8 f4 32 00 00 6a 09 8d 45 e9 50 e8 30 30 00 00 8d 45 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_NAH_2147597243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.NAH"
        threat_id = "2147597243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "nusrmgr.exe" ascii //weight: 10
        $x_10_2 = "http://liveupdatesnet.com/" ascii //weight: 10
        $x_10_3 = "MSVBVM60.DLL" ascii //weight: 10
        $x_1_4 = "HTTP/1.1" ascii //weight: 1
        $x_1_5 = "/m.php?aid=" ascii //weight: 1
        $x_1_6 = "vmwareservice.exe" ascii //weight: 1
        $x_1_7 = "loader.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_NAJ_2147597245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.NAJ"
        threat_id = "2147597245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sociedade\\novo pro\\loaderCriptVB\\Loader.vbp" wide //weight: 10
        $x_10_2 = "netsh firewall add allowedprogram" wide //weight: 10
        $x_10_3 = "YouTube" ascii //weight: 10
        $x_10_4 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_5 = "ShellExecuteA" ascii //weight: 10
        $x_10_6 = "MSVBVM60.DLL" ascii //weight: 10
        $x_1_7 = "Ftp..." wide //weight: 1
        $x_1_8 = "Emocoes_alegria" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_NAL_2147597278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.NAL"
        threat_id = "2147597278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_2 = "WriteProcessMemory" ascii //weight: 10
        $x_10_3 = "CreateRemoteThread" ascii //weight: 10
        $x_1_4 = "del \"c:\\myapp.exe\"" ascii //weight: 1
        $x_1_5 = "ping 127.0.0.1 >nul" ascii //weight: 1
        $x_1_6 = "if exist \"c:\\myapp.exe" ascii //weight: 1
        $x_1_7 = "\" goto try" ascii //weight: 1
        $x_1_8 = "c:\\myDelm.bat" ascii //weight: 1
        $x_1_9 = "360tray.exe" ascii //weight: 1
        $x_1_10 = "KRegEx.exe" ascii //weight: 1
        $x_1_11 = "KVXP.kxp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_AGB_2147597423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AGB"
        threat_id = "2147597423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "90"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "strip_girl" ascii //weight: 10
        $x_10_3 = "212.179.35.31" ascii //weight: 10
        $x_10_4 = "Software\\SGPlay" ascii //weight: 10
        $x_10_5 = ":\\program files\\internet explorer\\iexplore.exe" ascii //weight: 10
        $x_10_6 = "WriteProcessMemory" ascii //weight: 10
        $x_10_7 = "ReadProcessMemory" ascii //weight: 10
        $x_10_8 = "WSAStartup" ascii //weight: 10
        $x_10_9 = "socket" ascii //weight: 10
        $x_1_10 = "incorrect honey! Lets try again?" ascii //weight: 1
        $x_1_11 = "Ok, lets start baby! Lets see if you can strip me :)." ascii //weight: 1
        $x_1_12 = "take off 1 of my xxx :)" ascii //weight: 1
        $x_1_13 = "Wait for new word, please, sweetie ;)" ascii //weight: 1
        $x_1_14 = "You need to enter word from image if you want to see me naked ;)" ascii //weight: 1
        $x_1_15 = "I'm 18 years old and you have come to the" ascii //weight: 1
        $x_1_16 = "Easy, enter the code that you will see and I'm taking off" ascii //weight: 1
        $x_1_17 = "1 of my things. :) Want to start strip me? Then what are you" ascii //weight: 1
        $x_1_18 = "waiting for? Click the start play." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_NAM_2147597593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.NAM"
        threat_id = "2147597593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\SkypeClient.exe" ascii //weight: 10
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_3 = "ShellExecuteA" ascii //weight: 10
        $x_10_4 = "\\wininit.ini" ascii //weight: 10
        $x_1_5 = "\\my_70008.exe" ascii //weight: 1
        $x_1_6 = "\\s02.exe" ascii //weight: 1
        $x_1_7 = "\\dodolook349.exe" ascii //weight: 1
        $x_1_8 = "\\ad_2374.exe" ascii //weight: 1
        $x_1_9 = "\\setup1166.exe" ascii //weight: 1
        $x_1_10 = "\\shuigenet_cb.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_NAN_2147598236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.NAN"
        threat_id = "2147598236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "onlysex." ascii //weight: 5
        $x_2_2 = "\\msvsres.dll" ascii //weight: 2
        $x_2_3 = "www.msnprotection.com" ascii //weight: 2
        $x_2_4 = "www.msnhelper.net" ascii //weight: 2
        $x_2_5 = "/flushdns" ascii //weight: 2
        $x_2_6 = "/registerdns" ascii //weight: 2
        $x_2_7 = "www.pcspyremover.com/help/ref.php" ascii //weight: 2
        $x_2_8 = "www.nomorepcspies.com/help/ref.php" ascii //weight: 2
        $x_2_9 = "Software\\Microsoft\\Internet Explorer\\Settings" ascii //weight: 2
        $x_2_10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\explorer\\browser helper objects" ascii //weight: 2
        $x_2_11 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 2
        $x_1_12 = "happy-movies.com" ascii //weight: 1
        $x_1_13 = "hardmovies.net" ascii //weight: 1
        $x_1_14 = "birdmovies.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((10 of ($x_2_*))) or
            ((1 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 8 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_NAO_2147598237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.NAO"
        threat_id = "2147598237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "71"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%SystemRoot%\\system32\\drivers\\pcihdd.sys" ascii //weight: 10
        $x_10_2 = "%SystemRoot%\\System32\\Userinit.exe" ascii //weight: 10
        $x_10_3 = "WriteFile" ascii //weight: 10
        $x_10_4 = "RtlZeroMemory" ascii //weight: 10
        $x_10_5 = "OpenServiceA" ascii //weight: 10
        $x_10_6 = "DeleteFileA" ascii //weight: 10
        $x_10_7 = "DeleteService" ascii //weight: 10
        $x_1_8 = {c7 42 0c 6d 2f 74 65 c7 42 10 73 74 2e 63 c7 42 14 65 72 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_ACT_2147598410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ACT"
        threat_id = "2147598410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "D2FAC024-92C0-42E5-A75B-7B4E3915CC50" ascii //weight: 1
        $x_1_3 = "microbillsys.com" ascii //weight: 1
        $x_1_4 = "mibrsys.exe" ascii //weight: 1
        $x_1_5 = "CreateMutexA" ascii //weight: 1
        $x_1_6 = "InternetGetConnectedState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_ACD_2147598445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.gen!ACD"
        threat_id = "2147598445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {20 6c dc 0e 1c a3 db 11 8a b9 08 00 20 0c 9a 66}  //weight: 3, accuracy: High
        $x_3_2 = {55 52 4c 20 43 68 61 6e 67 65 72 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 3, accuracy: High
        $x_2_3 = "http://soft.trustincash.com/url/config.xml" ascii //weight: 2
        $x_2_4 = "CChangerBHO tries to perform start actions" ascii //weight: 2
        $x_2_5 = "LastCfgFetch" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_ACE_2147598447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.gen!ACE"
        threat_id = "2147598447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "WScript" ascii //weight: 10
        $x_1_2 = "Rdu!e`ud<$e`ud$" ascii //weight: 1
        $x_1_3 = {73 64 66 21 60 65 65 21 49 4a 44 58 5e 4d 4e 42 40 4d 5e 4c 40 42 49 48 4f 44 5d 52 4e 47 55 56 40 53 44 5d 4c 48 42 53 4e 52 4e 47 55 5d 56 48 4f 45 4e 56 52 5d 42 54 53 53 44 4f 55 57 44 53 52 48 4e 4f 5d 53 54 4f 21 2e 57 21 52 57 42 49 4e 52 55 52 2f 44 59 44 21 2e 55 21 53 44 46 5e 52 5b 21 2e 45 21 42 3b 5d 56 48 4f 45 4e 56 52 5d 52 58 52 55 44 4c 32 33 5d [0-16] 44 59 44 21 2e 47}  //weight: 1, accuracy: Low
        $x_1_4 = "e`ud!08" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_ABE_2147598751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.gen!ABE"
        threat_id = "2147598751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_2 = "rundll32 %s Start" ascii //weight: 10
        $x_10_3 = "%s\\drivers\\%s.sys" ascii //weight: 10
        $x_2_4 = "Rsskplm" ascii //weight: 2
        $x_1_5 = "CreateServiceA" ascii //weight: 1
        $x_1_6 = "live.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_ABE_2147598751_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.gen!ABE"
        threat_id = "2147598751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "olwnrf96.dll" ascii //weight: 30
        $x_5_2 = "\\%s.sys" ascii //weight: 5
        $x_5_3 = "%s\\\\drivers" ascii //weight: 5
        $x_5_4 = "%s\\\\%s.dll" ascii //weight: 5
        $x_5_5 = "CreateServiceA" ascii //weight: 5
        $x_5_6 = "c:\\windows\\system32\\\\drivers\\\\" ascii //weight: 5
        $x_1_7 = "live.dll" ascii //weight: 1
        $x_1_8 = "catclogd.dll" ascii //weight: 1
        $x_1_9 = "state.dll" ascii //weight: 1
        $x_1_10 = "live.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 5 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_NAQ_2147598813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.NAQ"
        threat_id = "2147598813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 63 63 68 6f 73 74 44 6f 63 [0-32] 43 63 63 68 6f 73 74 56 69 65 77 [0-32] 63 63 68 6f 73 74 2e 65 78 65 [0-32] 70 68 70 2e [0-16] 2f 68 63 74 61 77 65 74 6f 6d 65 72 2f 74 65 6e 2e [0-32] 2f 2f 3a 70 74 74 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_NZ_2147598844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.NZ"
        threat_id = "2147598844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "102"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WriteFile" ascii //weight: 1
        $x_1_2 = "RegSetValueExA" ascii //weight: 1
        $x_100_3 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 00 25 53 59 53 54 45 4d 52 4f 4f 54 25 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 64 6c 6c 00 00 00 5f 48 69 64 65 50 72 6f 63 65 73 73 40 34 00 00 00 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00 00 00 00 43 6f 6f 6b 69 65 73 00 5c 00 00 00 69 6e 64 65 78 2e 64 61 74 00 00 00 72 62 00 00 77 77 77 2e 61 76 2d 6b 69 6e 67 2e 6e 65 74}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_ZAG_2147599305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ZAG"
        threat_id = "2147599305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "GenProtect.dll" ascii //weight: 10
        $x_10_2 = "GenProtect.exE" ascii //weight: 10
        $x_5_3 = "mixerSetControlDetails" ascii //weight: 5
        $x_5_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 5
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
        $x_1_6 = "ReadProcessMemory" ascii //weight: 1
        $x_1_7 = "OpenProcess" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_ZAN_2147600328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ZAN"
        threat_id = "2147600328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_2 = "http://new.749571.com/xin.txt" ascii //weight: 10
        $x_10_3 = {b2 61 b1 65 c6 45 ?? 75 c6 45 ?? 72 88 45 ?? c6 45 ?? 6d c6 45 ?? 2e}  //weight: 10, accuracy: Low
        $x_6_4 = {8b d2 8b c9 8b c9 90 8b d2 8d 85 ?? ?? ff ff 68 04 01 00 00 50 6a 00 ff 15 ?? ?? ?? 00 8d 8d ?? ?? ff ff 6a 5c 51 ff 15 ?? ?? ?? 00}  //weight: 6, accuracy: Low
        $x_3_5 = "strrchr" ascii //weight: 3
        $x_3_6 = "InternetOpenA" ascii //weight: 3
        $x_3_7 = "WinExec" ascii //weight: 3
        $x_3_8 = "#32770" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_3_*))) or
            ((2 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_3_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*))) or
            ((3 of ($x_10_*) and 1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_PL_2147600530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.PL"
        threat_id = "2147600530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\SystemRoot\\system32\\drivers\\sysdt.sys" wide //weight: 1
        $x_1_2 = {52 49 4e 47 30 45 58 45 00 00 00 00 74 65 6d 70 64 69 72 2e 65 78 65 00 52 49 4e 47 30 42 49 4e 00 00 00 00 52 49 4e 47 30 00 00 00 25 73 5c 64 72 69 76 65 72 73 5c 25 73}  //weight: 1, accuracy: High
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_4 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_5 = "ntdll.dll" ascii //weight: 1
        $x_1_6 = "IoCreateFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_ZB_2147601084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ZB"
        threat_id = "2147601084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {77 69 6e 73 79 73 2e 72 65 67 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 00 00 61 76 70 2e 65 78 65 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73}  //weight: 10, accuracy: High
        $x_1_2 = "DC3D30AE-0380-4151-8934-EE98A34B0370" ascii //weight: 1
        $x_1_3 = "8C41B7F7-3168-400D-A702-0E7EFE0BA304" ascii //weight: 1
        $x_1_4 = "CAED0F3B-DF8B-4DBF-BB20-8DFBC3199068" ascii //weight: 1
        $x_1_5 = "82738577-2320-47A8-8593-645541D48BCD" ascii //weight: 1
        $x_1_6 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? ?? ?? ?? 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_AHA_2147601495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AHA"
        threat_id = "2147601495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HACKED!" wide //weight: 10
        $x_10_2 = "Your PC is soon dying. Sorry!" wide //weight: 10
        $x_10_3 = "format d: /autotest /q /u" wide //weight: 10
        $x_10_4 = "del c:\\windows\\system32\\hal.dll" wide //weight: 10
        $x_1_5 = "ugly.Resources" wide //weight: 1
        $x_1_6 = "Heuristic Anti-Virus Scanner PRO" wide //weight: 1
        $x_1_7 = "shutdown -r -c \"Windows has expired" wide //weight: 1
        $x_1_8 = "Incompatible antivirus installed. Please remove or turn it off." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_AHC_2147601643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AHC"
        threat_id = "2147601643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET ^%$%^&**(*((&&*^&&%%^&*(*&$%$^%$#^*^%$##$.htmGET ^*%%RFTGYHJIRTG*(&^%DFG(JKJHJ%^&*()*&*^&%.aspGET *(&*^TGH*JIHG^&*(&^%*(*)OK)(*&^%$EDRGF%&^.html" ascii //weight: 1
        $x_1_2 = "Referer: http://www.google.com" ascii //weight: 1
        $x_1_3 = "Referer: http://www.baidu.com" ascii //weight: 1
        $x_1_4 = "Cache-Control: no-cache" ascii //weight: 1
        $x_1_5 = "\\systom32\\svchost.exe" ascii //weight: 1
        $x_1_6 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_8 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_9 = "c:\\pagefile.pif" ascii //weight: 1
        $x_1_10 = "\\cmd.exe /c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Agent_N_2147603111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.gen!N"
        threat_id = "2147603111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 81 ec 00 02 00 00 80 a5 00 ff ff ff 00 56 57 6a 3f 59 33 c0 8d bd 01 ff ff ff 80 a5 00 fe ff ff 00 f3 ab 66 ab aa 6a 3f 33 c0 59 8d bd 01 fe ff ff f3 ab 66 ab aa 8d 85 00 fe ff ff 68 04 01 00 00 50 ff 15 ?? ?? 40 00 8d 85 00 fe ff ff 68 ?? ?? 40 00 50 e8 64 03 00 00 8d 85 00 fe ff ff 50 e8 ?? ?? ?? ?? 83 c4 0c 84 c0}  //weight: 10, accuracy: Low
        $x_10_2 = {7e 74 69 00 2e 4c 6f 47 00 00 00 00 2e 64 6c 6c}  //weight: 10, accuracy: High
        $x_10_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 00 00 4b 61 76 00 72 65 67 65 64 69 74 20 2f 73 20 00 22 3d 22 22 00 00 00 00 22 00 00 00 5b 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 5d}  //weight: 10, accuracy: High
        $x_1_4 = "winsys.reg" ascii //weight: 1
        $x_1_5 = "C:\\WINDOWS\\SYSTEM32\\tmpFile" ascii //weight: 1
        $x_1_6 = "EnumProcesses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_AIA_2147603191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AIA"
        threat_id = "2147603191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {b8 46 55 43 4b 3d 46 55 43 4b 75}  //weight: 100, accuracy: High
        $x_10_2 = "FUCK=FUCK" ascii //weight: 10
        $x_10_3 = "fuckallblya" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_AEZ_2147603567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AEZ"
        threat_id = "2147603567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c u later" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "C:\\kernelcheck.exe" ascii //weight: 1
        $x_1_4 = "shell\\Auto\\command=autorun.exe" ascii //weight: 1
        $x_1_5 = "magnet\\shell\\open\\command" ascii //weight: 1
        $x_1_6 = "C:\\TEMP\\\\sysfnx.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_PQ_2147604805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.PQ"
        threat_id = "2147604805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {72 75 6e 64 6c 6c 33 32 20 79 69 6e 68 75 2e 64 6c 6c 20 49 6e 73 74 61 6c 6c 20 0d 0a 20 6e 65 74 20 73 74 61 72 74 20 49 50 52 49 50 0d 0a 00 77 62 2b 00 5c 79 69 6e 68 75 2e 62 61 74 00 00 62 61 74 2e 62 61 74}  //weight: 10, accuracy: High
        $x_10_2 = "C:\\WINDOWS\\SYSTEM32\\yinhu.bat" ascii //weight: 10
        $x_10_3 = "LengFengTrojan" ascii //weight: 10
        $x_1_4 = "RESETHOST is ok" ascii //weight: 1
        $x_1_5 = "RegSetValueEx(ServiceDll)" ascii //weight: 1
        $x_1_6 = "SvcHost.DLL.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_PS_2147604886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.PS"
        threat_id = "2147604886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 6c 6f 62 61 6c 5c 25 73 2d 6b 65 79 2d 6d 65 74 75 78 00 47 6c 6f 62 61 6c 5c 25 73 2d 6b 65 79 2d 65 76 65 6e 74}  //weight: 1, accuracy: High
        $x_1_2 = "POST http://%s:%d/%s HTTP/1.1" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" ascii //weight: 1
        $x_1_4 = "SYSTEM\\ControlSet001\\Services\\%s" ascii //weight: 1
        $x_1_5 = {48 66 44 6f 4d 61 69 6e 57 6f 72 6b 00 48 66 44 6f 53 65 72 76 69 63 65 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_6 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_7 = "CallNextHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_ZDD_2147604888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ZDD"
        threat_id = "2147604888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PR.EXE 192.168.0.1 1-65535 -d:1 -e" ascii //weight: 1
        $x_1_2 = "http://webipcha.cn/tongji/tj/s/1.asp?mac=" wide //weight: 1
        $x_1_3 = "Por.aed" wide //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\360Safetray" wide //weight: 1
        $x_1_5 = "sc config wscsvc start= disabled&net stop KPfwSvc&net stop KWatchsvc&net stop McShield&net stop \"Norton AntiVirus Server\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Agent_PT_2147605584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.PT"
        threat_id = "2147605584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6d 73 6e 6d 73 67 72 2e 65 78 65 00 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 44 69 72 65 63 74 6f 72 79 00 00 00 5c 4d 53 4e 4d 65 73 73 65 6e 67 65 72 5c 00 00 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 48 54 54 50 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 00 00 00 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 10, accuracy: High
        $x_1_2 = "CreateRemoteThread" ascii //weight: 1
        $x_1_3 = "RegSetValueExA" ascii //weight: 1
        $x_1_4 = "RegCreateKeyExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_CR_2147608028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.CR"
        threat_id = "2147608028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SuperHidden" ascii //weight: 10
        $x_10_2 = "/c del C:\\myapp.exe > nul" ascii //weight: 10
        $x_10_3 = "Framework Microsoft Check" wide //weight: 10
        $x_10_4 = "\\microsoft\\serv\\sysecc.exe" wide //weight: 10
        $x_10_5 = "foto pornografiche da scaricare" wide //weight: 10
        $x_1_6 = "RasDialA" ascii //weight: 1
        $x_1_7 = "ShellExecuteExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_CS_2147608031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.CS"
        threat_id = "2147608031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "172"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_10_2 = "@msn.com.br" ascii //weight: 10
        $x_10_3 = "msnmsgr.exe" ascii //weight: 10
        $x_10_4 = "MsnHelperObj" ascii //weight: 10
        $x_10_5 = "RemoteMachineName" ascii //weight: 10
        $x_10_6 = "WSAStartup" ascii //weight: 10
        $x_10_7 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_8 = "Toolhelp32ReadProcessMemory" ascii //weight: 10
        $x_1_9 = "avgcc.exe" ascii //weight: 1
        $x_1_10 = "NAVW32.EXE" ascii //weight: 1
        $x_1_11 = "NPFMNTOR.EXE" ascii //weight: 1
        $x_1_12 = "SNDSrvc.exe" ascii //weight: 1
        $x_1_13 = "CCAPP.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 7 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_PU_2147608215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.PU"
        threat_id = "2147608215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 25 73 22 20 2d 68 69 64 65 00 00 22 25 73 22 00 00 00 00 49 6e 73 74 61 6c 6c 65 72 3a 20 44 53 54 2d 44 61 74 65 69 20 25 73 3a 20 25 73}  //weight: 1, accuracy: High
        $x_1_2 = "CMD: get..." ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "connect(): status=%d" ascii //weight: 1
        $x_1_5 = {33 c0 8d 7c 24 20 ab ab ab ab 0f bf 4a 0a 8b 42 0c 8d 7c 24 24 8b 30 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_DM_2147608217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.DM"
        threat_id = "2147608217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "232"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {81 fa ff 00 00 00 7f 02 30 10 8b fa 81 e7 01 00 00 80 79 05 4f 83 cf fe 47 85 ff 75 05}  //weight: 100, accuracy: High
        $x_100_2 = {69 66 20 65 78 69 73 74 20 22 00 00 22 20 67 6f 74 6f 20 4c 6f 6f 70 0d 0a 00 00 00 64 65 6c 20}  //weight: 100, accuracy: High
        $x_10_3 = "Wow.exe" ascii //weight: 10
        $x_10_4 = "Win32 only!" ascii //weight: 10
        $x_10_5 = "{6A041F13-A111-12A3" ascii //weight: 10
        $x_1_6 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_DO_2147608385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.DO"
        threat_id = "2147608385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "title LOL" ascii //weight: 10
        $x_10_2 = "batfile.bat" ascii //weight: 10
        $x_10_3 = "batchfile.bat" ascii //weight: 10
        $x_10_4 = "del c:\\WINDOWS\\system32\\drivers\\etc\\hosts" ascii //weight: 10
        $x_10_5 = "copy hosts c:\\WINDOWS\\system32\\drivers\\etc\\hosts" ascii //weight: 10
        $x_10_6 = ">>%windir%\\System32\\drivers\\etc\\hosts" ascii //weight: 10
        $x_1_7 = "echo 75.127.83." ascii //weight: 1
        $x_1_8 = "echo 75.127.85." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_DP_2147608386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.DP"
        threat_id = "2147608386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "150"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {f3 ab 66 ab aa c6 85 ?? ff ff ff 5c c6 85 ?? ff ff ff 73 c6 85 ?? ff ff ff 76 c6 85 ?? ff ff ff 63 c6 85 ?? ff ff ff 68 c6 85 ?? ff ff ff 6f c6 85 ?? ff ff ff 73 c6 85 ?? ff ff ff 74 c6 85 ?? ff ff ff 2e c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 78 c6 85 ?? ff ff ff 65 80 a5 ?? fe ff ff 00 6a 3f}  //weight: 100, accuracy: Low
        $x_10_2 = "DoService" ascii //weight: 10
        $x_10_3 = "OpenServiceA" ascii //weight: 10
        $x_10_4 = "OpenSCManagerA" ascii //weight: 10
        $x_10_5 = "Yahoo! messenger" ascii //weight: 10
        $x_10_6 = "2008 Yahoo! All Rights Reserved" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_DR_2147608443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.DR"
        threat_id = "2147608443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Desktop\\[-MSN-]\\Msn" wide //weight: 1
        $x_1_2 = "\\VolumeControl.vbp" wide //weight: 1
        $x_1_3 = "myfot0s.ifrance.com" ascii //weight: 1
        $x_1_4 = {56 6f 6c 75 6d 65 43 6f 6e 74 72 6f 6c 31 ?? ?? ?? ?? 56 6f 6c 43 6f 6e 74 72 6f 6c 2e 56 6f 6c 75 6d 65 43 6f 6e 74 72 6f 6c}  //weight: 1, accuracy: Low
        $x_1_5 = {6d 73 6e 6d 73 67 73 00 57 69 6e 64 6f 77 73 20 4c 69 76 65 20 4d 65 73 73 65 6e 67 65 72 00 00 50 72 6f 79 65 63 74 6f 31}  //weight: 1, accuracy: High
        $x_1_6 = "TrocarEmailsSend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Agent_DX_2147608777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.DX"
        threat_id = "2147608777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 3b 4a 0f 85 ?? ?? ?? ?? 80 7b 01 46 0f 85 ?? ?? ?? ?? 80 7b 02 49 0f 85 ?? ?? ?? ?? 80 7b 03 46 0f 85 ?? ?? ?? ?? 80 7b 04 00 0f 85}  //weight: 2, accuracy: Low
        $x_1_2 = "bsclickw1er123145" wide //weight: 1
        $x_1_3 = "360try1" wide //weight: 1
        $x_2_4 = "gtskinfo.aspx?ver=3.3&t=rb&m=" wide //weight: 2
        $x_1_5 = "\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_DY_2147608790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.DY"
        threat_id = "2147608790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56}  //weight: 4, accuracy: High
        $x_1_2 = "Remote_2010.08.03" ascii //weight: 1
        $x_1_3 = "!*_*->seven-eleven<-*_*!" ascii //weight: 1
        $x_1_4 = "%s%s%s(%d)%s" ascii //weight: 1
        $x_1_5 = "%s%d.dat" ascii //weight: 1
        $x_1_6 = "\\xxxxxxx.dbg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_EL_2147610394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.EL"
        threat_id = "2147610394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {64 65 6c 73 65 6c 66 2e 62 61 74 00 64 33 32 64 78 39 2e 73 79 73}  //weight: 4, accuracy: High
        $x_4_2 = {53 68 65 6c 6c 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e}  //weight: 4, accuracy: High
        $x_2_3 = "mb.asp?a=1&c=" ascii //weight: 2
        $x_2_4 = {25 73 25 73 00 78 79 6d 61 69 6e 2e 62 69 6e}  //weight: 2, accuracy: High
        $x_1_5 = "HttpSendRequestA" ascii //weight: 1
        $x_1_6 = "InternetConnectA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_EQ_2147611028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.EQ"
        threat_id = "2147611028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "help.dll" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup" ascii //weight: 1
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Services\\BITS\\Parameters" ascii //weight: 1
        $x_1_4 = "SYSTEM\\ControlSet003\\Services\\BITS\\Parameters" ascii //weight: 1
        $x_1_5 = "Free DLL Done!" ascii //weight: 1
        $x_1_6 = "DisableRegistryTools" ascii //weight: 1
        $x_1_7 = "winmm.dll" ascii //weight: 1
        $x_1_8 = {52 65 6d 6f 74 65 20 6e 65 74 43 6f 6e 74 72 6f 6c 20 53 65 72 76 69 63 65 3c 2f 64 69 73 3e 3c 64 65 73 3e 72 65 6d 6f 74 65 20 6e 65 74 77 6f 72 6b 20 26 20 63 6f 6e 63 74 72 6f 6c 20 73 65 72 76 69 63 65 3c 2f 64 65 73 3e 3c 69 6e 66 3e [0-80] 3a}  //weight: 1, accuracy: Low
        $x_1_9 = "Q360SafeMonClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_ET_2147621748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ET"
        threat_id = "2147621748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "phar-100" ascii //weight: 1
        $x_1_2 = "WindowsApplication1.Resources" wide //weight: 1
        $x_1_3 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "http://www.design-unleashed.com/administrator/images/backupo.txt" wide //weight: 1
        $x_1_5 = "C:\\WINDOWS\\Help\\Cache.exe" wide //weight: 1
        $x_1_6 = "explorer http://www.nextel.com.mx/" wide //weight: 1
        $x_1_7 = "C:\\WINDOWS\\system32\\drivers\\etc\\hosts" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Agent_EU_2147622232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.EU"
        threat_id = "2147622232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 63 00 6f 00 6e 00 69 00 6d 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: High
        $x_1_3 = "HNetCfg.FwMgr" ascii //weight: 1
        $x_1_4 = "HNetCfg.FwAuthorizedApplication" ascii //weight: 1
        $x_1_5 = "recvfrom" ascii //weight: 1
        $x_1_6 = "cmd=click0ok" ascii //weight: 1
        $x_1_7 = "cmd=execok" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_ASG_2147622447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.ASG"
        threat_id = "2147622447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\drivers\\vmmouse.sys" ascii //weight: 1
        $x_1_2 = " !.\\sDO" ascii //weight: 1
        $x_1_3 = "asdf456565634645" ascii //weight: 1
        $x_1_4 = ".mixcrt" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\KasperskyLab\\AVP6" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\KasperskyLab\\AVP7" ascii //weight: 1
        $x_1_7 = "dyqmnsds/dyd" ascii //weight: 1
        $x_1_8 = "\\system32\\drivers\\gmreadme.txt" ascii //weight: 1
        $x_1_9 = "SOFTWARE\\KasperskyLab\\protected\\AVP8" ascii //weight: 1
        $x_1_10 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\sdtr" wide //weight: 1
        $x_1_11 = "`.usdfdf5" ascii //weight: 1
        $x_1_12 = "\\system32\\drivers\\sdtr.sys" ascii //weight: 1
        $x_1_13 = "SOFTWARE\\KasperskyLab\\protected\\AVP7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_EV_2147622823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.EV"
        threat_id = "2147622823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Device\\PhysicalMemory" wide //weight: 1
        $x_1_2 = {8b 45 08 a3 ?? ?? ?? ?? 8b 45 0c ff 1d ?? ?? ?? ?? 8b 45 0c 8b 4d 08 50 51 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 01 45 f8 8b 4d fa 8d 45 08 50 51 e8 ?? ?? ff ff 8b 75 f8 8b 55 08 81 e6 ff ff 00 00 83 c4 08 8d 0c 16 51 50 6a 00 6a 06 57 ff 15 ?? ?? ?? ?? 85 c0 a3 ?? ?? ?? ?? 75 08 5f 32 c0 5e 8b e5 5d c3 8b 55 08 bf 00 ff 00 00 8d 4c 10 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_EW_2147623783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.EW"
        threat_id = "2147623783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 74 2f 8b 8d ?? ?? ?? ?? 0f be 91 ?? ?? ?? ?? 83 f2 77 85 d2 74 1b 8b 85 ?? ?? ?? ?? 8a 88 ?? ?? ?? ?? 80 f1 77 8b 95 ?? ?? ?? ?? 88 8a ?? ?? ?? ?? eb a3}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 02 34 21 8b 8d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01 eb c3 8b 15 ?? ?? ?? ?? 52 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_EX_2147624074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.EX"
        threat_id = "2147624074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "systempz.ini" ascii //weight: 1
        $x_1_2 = {80 f9 3a 75 47 c6 84 05 ?? ?? ?? ?? 00 8a 8c 05 ?? ?? ff ff 40 80 f9 2f c7 45 ?? 01 00 00 00 75 1c 8a 8c 05 ?? ?? ff ff 40 80 f9 2f 75 2d 40}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 01 8a d0 3a 06 75 1c 84 d2 74 14 8a 41 01 8a d0 3a 46 01 75 0e 83 c1 02 83 c6 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_FS_2147624640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.FS"
        threat_id = "2147624640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 12 0f b6 44 02 ff 89 45 e8 c7 45 ec 22 00 00 00 0f b7 45 f0 c1 e8 08 89 45 e4 c7 45 ec 4f 03 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {29 d0 c1 e0 02 89 c1 58 8b 40 18 8d 04 90 7c 0a 50 8d 50 04}  //weight: 1, accuracy: High
        $x_1_3 = {03 c2 89 45 dc db 45 dc d8 35 ?? ?? 40 00 de c1 8b 45 f8 dd 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_GA_2147625443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.GA"
        threat_id = "2147625443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 47 fe 50 e8 ?? ?? ?? ?? 83 c4 04 85 c0 0f 8c ?? ?? ?? ?? 8a 4f ff c1 e0 06 51 8b f0 e8 ?? ?? ?? ?? 83 c4 04 85 c0 0f 8c ?? ?? ?? ?? 03 f0 8a 07 c1 e6 06 3c 3d}  //weight: 10, accuracy: Low
        $x_10_2 = "software\\mICROSOFT\\wINDOWS nt\\cURRENTvERSION\\sVCHOST" ascii //weight: 10
        $x_10_3 = "%sYSTEMrOOT%\\sYSTEM32\\SVCHOST.EXE -K NETSVCS" ascii //weight: 10
        $x_1_4 = "vnw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_EEC_2147626767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.EEC"
        threat_id = "2147626767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 8d 85 ?? ?? ff ff 50 68 00 2a 00 00 68 ?? ?? 40 00 8b 8d ?? ?? ff ff 51 8b 95 ?? ?? ff ff 8b 82 ?? 00 00 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {68 67 6d 56 40 8b 4d ?? e8 ?? ?? 00 00 8b 4d ?? 89 41 40 68 81 69 4c 21 8b 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_HG_2147635817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.HG"
        threat_id = "2147635817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {73 70 79 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 3, accuracy: High
        $x_2_2 = "Global\\asdfwee" wide //weight: 2
        $x_1_3 = {72 62 2b 00 57 00 69 00 6e 00 53 00 74 00 61 00 30}  //weight: 1, accuracy: High
        $x_2_4 = "svchost.dll" ascii //weight: 2
        $x_2_5 = "/vip/1312/ip.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_AAH_2147635918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AAH"
        threat_id = "2147635918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e8 05 74 2c 48 74 5f 83 e8 51 74 7e 83 e8 24 74 67}  //weight: 1, accuracy: High
        $x_1_2 = "Internet Connection Sharing (ICA)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_HI_2147636354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.HI"
        threat_id = "2147636354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 e0 3c 5f 77 ?? 83 e0 7f 0f a3}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fe 42 75 2d f7 c7 00 00 00 80 75 25}  //weight: 1, accuracy: High
        $x_1_3 = "&pass=" ascii //weight: 1
        $x_1_4 = "http://20vp.cn/moyu/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Agent_QM_2147637762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.QM"
        threat_id = "2147637762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 39 68 75 12 80 79 05 ff 75 0c 80 79 06 15 75 06 80 79 0b e9 74}  //weight: 1, accuracy: High
        $x_2_2 = {33 41 04 99 f7 fb 8a 06 f6 d0 32 d0 47}  //weight: 2, accuracy: High
        $x_1_3 = "test.3322.org" ascii //weight: 1
        $x_1_4 = "\\1EXPLORE.EXE" ascii //weight: 1
        $x_1_5 = {ce a2 b5 e3 d6 f7 b6 af b7 c0 d3 f9 c8 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_QN_2147637763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.QN"
        threat_id = "2147637763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 40 16 25 ff df 00 00 8b 4d ?? 66 89 41 16 eb 13}  //weight: 1, accuracy: Low
        $x_2_2 = {6a ff 8d 85 ?? ?? ff ff ?? 6a 00 68 ?? ?? ?? 00 8b ff 55 a1 ?? ?? ?? 00 83 c0 03 ff e0}  //weight: 2, accuracy: Low
        $x_1_3 = {83 7d 10 65 75 07 c7 45 ?? f5 04 00 00 83 7d 10 66 75 07 c7 45 ?? 27 07 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\\\.\\Reroot" ascii //weight: 1
        $x_1_5 = "http://%s:%d/%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_AAE_2147638557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AAE"
        threat_id = "2147638557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 08 8b 46 3c 8b 44 30 78 03 c6 8b ?? 1c 8b ?? 20 8b ?? 24 8b ?? 18}  //weight: 1, accuracy: Low
        $x_1_2 = {29 45 08 8b 45 08 c1 c8 07 89 45 08 ff 45}  //weight: 1, accuracy: High
        $x_1_3 = {0f 84 07 00 00 00 0f 85 01 00 00 00 e8 0f b6 85 ?? ?? ff ff 83 e0 0f}  //weight: 1, accuracy: Low
        $x_1_4 = {83 f8 72 75 ?? 0f be 85 ?? ?? ff ff 83 f8 03 75 2a 0f be 85 ?? ?? ff ff 83 f8 73 75 1e 0f be 85 83 ea ff ff 83 f8 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Agent_QP_2147639600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.QP"
        threat_id = "2147639600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 1a ff 80 f2 58 88 54 18 ff 43 4e 75 e1}  //weight: 2, accuracy: High
        $x_1_2 = {85 c0 0f 84 ?? ?? 00 00 c7 05 ?? ?? ?? ?? 07 00 01 00}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 47 65 74 50 39 06 75 f1 b8 72 6f 63 41 39 46 04}  //weight: 1, accuracy: High
        $x_1_4 = {75 f7 ff 02 48 75 f4 8b 02 59 5d c3}  //weight: 1, accuracy: High
        $x_1_5 = "ravmond.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_QQ_2147639603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.QQ"
        threat_id = "2147639603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 30 80 c2 7a 88 14 30 8b 45 ?? 80 34 30 19}  //weight: 1, accuracy: Low
        $x_1_2 = "HACK590NETSVCS_0x%x" ascii //weight: 1
        $x_1_3 = "%sYSTEMrOOT%\\sYSTEM32\\SVCHOST.EXE -K NETSVCS" ascii //weight: 1
        $x_1_4 = "%s\\pcgame.dll" ascii //weight: 1
        $x_1_5 = "WHM_Server_Update" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Agent_RF_2147640163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.RF!dll"
        threat_id = "2147640163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b1 6c 32 c0 c6 45 e0 73 c6 45 e1 68 88 4d e2 c6 45 e3 77 88 45 e4 88 45 e5 c6 45 e6 69 c6 45 e7 2e c6 45 e8 64 88 4d e9 88 4d ea 88 45 eb 90 90 c6 45 e4 61 c6 45 e5 70}  //weight: 1, accuracy: High
        $x_1_2 = "%s\\%z4^<d.lnk" ascii //weight: 1
        $x_1_3 = "Uz4^<RLDz4^<ownz4^<loaz4^<dToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_AAI_2147640530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AAI"
        threat_id = "2147640530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "360se_Frame" ascii //weight: 1
        $x_1_2 = " system32\\ime\\ping -n " ascii //weight: 1
        $x_1_3 = "echo WScript.CreateObject(^\"WScript.Shell^\").Run(^\"cmd /c xcopy" ascii //weight: 1
        $x_1_4 = "echo CreateObject(\"wscript.shell\").run \"cmd.exe /c regedit/s" ascii //weight: 1
        $x_1_5 = "^\"^&Chr(34)),vbHide>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Agent_AFZ_2147641496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AFZ"
        threat_id = "2147641496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cenc\\ADODB.dll" ascii //weight: 1
        $x_1_2 = "hoct_updata.exe" ascii //weight: 1
        $x_1_3 = "bao.lylwc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_EAB_2147641875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.EAB"
        threat_id = "2147641875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 48 3c 8b 7c 01 78 03 f8 8b 77 24 8b 4f 1c 8b 57 20 8b 5f 18 03 f0 89 75 ?? 8b 77 14 03 c8 03 d0 89 45 ?? 89 4d ?? 89 55}  //weight: 2, accuracy: Low
        $x_1_2 = {0f b7 40 0e 8b 4d ?? 0f b7 49 0c 03 c1 39 45}  //weight: 1, accuracy: Low
        $x_1_3 = "_Append_Text_Value@12" ascii //weight: 1
        $x_1_4 = "_Clear_DataText@8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_EAC_2147641877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.EAC"
        threat_id = "2147641877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {51 51 bb e1 d4 b1 a1 a2 ba ec d7 ea a1 a2 bb c6 d7 ea a1 a2 c2 cc d7 ea c3 e2 b7 d1 cb a2}  //weight: 4, accuracy: High
        $x_1_2 = "scvhosr.exe" wide //weight: 1
        $x_1_3 = "_DDL_index.html" wide //weight: 1
        $x_1_4 = "QQVipOwner" wide //weight: 1
        $x_1_5 = "TencentConInfoFrame" wide //weight: 1
        $x_1_6 = "StartDownRun" ascii //weight: 1
        $x_1_7 = "ShiFang" ascii //weight: 1
        $x_1_8 = "QQShower" wide //weight: 1
        $x_1_9 = "goto Repeat" ascii //weight: 1
        $x_1_10 = "del %0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_EAD_2147641880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.EAD"
        threat_id = "2147641880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 1c 11 80 f3 11 88 1c 11 8b 54 24 ?? 8a 1c 11 80 c3 f0 88 1c 11 41 3b c8 7c d4}  //weight: 4, accuracy: Low
        $x_1_2 = ":\\angel.jpg" ascii //weight: 1
        $x_1_3 = "\\factory.dll" ascii //weight: 1
        $x_1_4 = {00 64 65 76 69 63 65 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = "\\MyInformations.ini" ascii //weight: 1
        $x_1_6 = {00 43 6f 6e 6e 65 63 74 48 6f 73 74}  //weight: 1, accuracy: High
        $x_1_7 = "%s\\~%cConnect%c%c.temp" ascii //weight: 1
        $x_1_8 = ":\\qqliveslog.scr" ascii //weight: 1
        $x_1_9 = "%s,CodeMain %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_EAE_2147641881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.EAE"
        threat_id = "2147641881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://you36.com/" ascii //weight: 1
        $x_1_2 = "C:\\netwj.rar" ascii //weight: 1
        $x_1_3 = "em32\\xznet.bat" ascii //weight: 1
        $x_1_4 = "/NETGOD_GX.EXE" ascii //weight: 1
        $x_1_5 = "WIN_cke.txt" ascii //weight: 1
        $x_1_6 = "fu_36c" ascii //weight: 1
        $x_1_7 = "my36 where jb=" ascii //weight: 1
        $x_1_8 = "\\win32.btl" ascii //weight: 1
        $x_1_9 = "dlc.exe" ascii //weight: 1
        $x_1_10 = "\\Startup\\" ascii //weight: 1
        $x_1_11 = "netgodrun.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Agent_EAF_2147641884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.EAF"
        threat_id = "2147641884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://222.73.36.68:8080" ascii //weight: 1
        $x_1_2 = "/default2.aspx?mac=" ascii //weight: 1
        $x_1_3 = "\\winuac.lnk" ascii //weight: 1
        $x_1_4 = "cdmi.ydc" ascii //weight: 1
        $x_1_5 = "ucd.cpm\" setconfig" ascii //weight: 1
        $x_1_6 = "lorer\\Quick Launch\\" ascii //weight: 1
        $x_1_7 = "\\Shell\\Open\\Command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Agent_HU_2147642454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.HU"
        threat_id = "2147642454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 8a 06 4e 8a 26 4e 32 c4 88 07 4f e2 f6 5f 5e}  //weight: 1, accuracy: High
        $x_1_2 = {74 19 68 00 00 04 00 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c3 6a 00 53 ff 75 f8 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 75 f8 6a 08 ff 75 fc ff 15 ?? ?? ?? ?? 0f b7 46 08 8d 04 45 0a 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 10 10 05 00 ff 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_IV_2147647222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.IV"
        threat_id = "2147647222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ch0colat" ascii //weight: 1
        $x_1_2 = "los hombr3sGG" ascii //weight: 1
        $x_1_3 = "C:\\choco\\late-p1elcelestia\\l-indeTe.DEM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_JD_2147647890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.JD"
        threat_id = "2147647890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {73 00 6f 00 66 00 74 00 77 00 00 00 61 00 72 00 65 00 5c 78 30 30 6d 00 69 00 63 00 72 00 00 00 00 00 6b 00 6a 00 65 00 77 00 6f 00 6f 00 70 00 69 00}  //weight: 5, accuracy: High
        $x_5_2 = {2e 00 69 00 6e 00 69 00 00 00 00 00 47 65 74 58 6f 72 43 68 65 63 6b 53 75 6d 31 36 00 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_JJ_2147649034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.JJ"
        threat_id = "2147649034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svch0st1.exe" ascii //weight: 1
        $x_1_2 = "s%\\pmeT\\SWODNIW\\:C" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\Internet Explorer\\ssmarque.scr" ascii //weight: 1
        $x_1_4 = "C:\\Program Files\\Internet Explorer\\carss.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_KM_2147655848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.KM"
        threat_id = "2147655848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 0c 01 75 38 68 00 20 00 00 6a 00 6a 00 6a 00 68 04 a1 00 00 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 68 2c 01 00 00 68 57 07 00 00 ff 75 08 ff 15 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {68 c2 01 00 00 68 f4 01 00 00 6a 64 6a 64 68 00 00 cf 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 89 45 cc 6a 00 ff 75 cc e8}  //weight: 1, accuracy: Low
        $x_1_3 = "Iraqeaa" ascii //weight: 1
        $x_1_4 = "D13956C45B94" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_KO_2147655992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.KO"
        threat_id = "2147655992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 76 50 6a 00 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 89 ?? fc fc 56 8b 4e 54 8b 75 08 8b ?? fc 33 c0 f3 a4 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {51 b9 b6 dc 0e 00 81 c1 1c 02 00 00 8b 45 d4 d1 c0 c1 c8 ?? 85 c0 c1 c0 ?? 50 8f 45 d4}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 00 cf 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 89 45 cc 6a 00 ff 75 cc e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_KQ_2147656584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.KQ"
        threat_id = "2147656584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "carlos" wide //weight: 1
        $x_1_2 = {4c 52 41 43 4d 31 00 00 4c 52 41 43 31}  //weight: 1, accuracy: High
        $x_1_3 = {68 fc 2e 40 00 a1 14 41 40 00 50 ff d7 8b f0 6a 0a 68 04 2f 40 00 a1 04 41 40 00 50 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_KU_2147657116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.KU"
        threat_id = "2147657116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Svchost.txt" ascii //weight: 10
        $x_10_2 = "\\Svchost.reg" ascii //weight: 10
        $x_1_3 = "Winds" ascii //weight: 1
        $x_1_4 = "\\hfsetemp.ini" ascii //weight: 1
        $x_1_5 = "\\%d_tem.info" ascii //weight: 1
        $x_1_6 = "\\esent.dll" ascii //weight: 1
        $x_1_7 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_KV_2147657199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.KV"
        threat_id = "2147657199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c:\\Win_laj.ini" ascii //weight: 1
        $x_1_2 = "%swindows\\xinstall%d.dll" ascii //weight: 1
        $x_1_3 = "Mjjxhj__Bjnl" ascii //weight: 1
        $x_1_4 = "MSN Security Guard Install" wide //weight: 1
        $x_1_5 = {ff 33 c6 85 ?? fe ff ff 36 c6 85 ?? fe ff ff 30 c6 85 ?? fe ff ff 53 c6 85 ?? fe ff ff 61 c6 85 ?? fe ff ff 66 c6 85 ?? fe ff ff 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_KZ_2147658184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.KZ"
        threat_id = "2147658184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RealAudo\\Ac97" ascii //weight: 1
        $x_1_2 = "CWEnject.exe" ascii //weight: 1
        $x_1_3 = "KGDaemom.exe" ascii //weight: 1
        $x_1_4 = "[##Microsoft##]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_M_2147741080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.M!MTB"
        threat_id = "2147741080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Qkkbal" ascii //weight: 1
        $x_1_2 = "%Mgr.RhY4RfE5Qd:f" ascii //weight: 1
        $x_1_3 = "extd.exe" ascii //weight: 1
        $x_1_4 = "::This file will teach how to make a virus?" ascii //weight: 1
        $x_1_5 = "s.bat" wide //weight: 1
        $x_1_6 = "os.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_DSK_2147742250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.DSK!MTB"
        threat_id = "2147742250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 8d f4 f7 ff ff 0f 44 c1 80 e2 c0 08 95 fa f7 ff ff a3 ?? ?? ?? ?? 81 f3 50 d0 a8 64 81 ad f4 f7 ff ff e6 23 75 66 c1 e0 04 81 85 f4 f7 ff ff 44 4f ea 10 81 85 f4 f7 ff ff a6 d4 8a 55}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_RRR_2147742971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.RRR!MTB"
        threat_id = "2147742971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lowsdkjgnh" ascii //weight: 1
        $x_1_2 = "elkrngfps" ascii //weight: 1
        $x_1_3 = "sdlofighapw9e8" ascii //weight: 1
        $x_1_4 = "dofhigaw0p9df8gmyq03984ytr0q9pwerht" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_PDSK_2147744122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.PDSK!MTB"
        threat_id = "2147744122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qemu-ga.exe" ascii //weight: 1
        $x_1_2 = "iplogger.org" ascii //weight: 1
        $x_1_3 = "track/glqkhzmp?sub=" ascii //weight: 1
        $x_1_4 = "\\postbackstat.exe" ascii //weight: 1
        $x_1_5 = "\\updater3.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_PA_2147744205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.PA!MTB"
        threat_id = "2147744205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dlshsvc.exe" ascii //weight: 1
        $x_1_2 = "ftshost.exe" ascii //weight: 1
        $x_1_3 = "mshost.exe" ascii //weight: 1
        $x_1_4 = "mstray.exe" ascii //weight: 1
        $x_1_5 = "\\\\.\\mailslot\\f2874324320878" ascii //weight: 1
        $x_1_6 = "add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /v Hidden /t REG_DWORD /d 0x00000000 /f" ascii //weight: 1
        $x_1_7 = "add %s\\%s /v %s /t REG_SZ /d \"%s\" /f" ascii //weight: 1
        $x_1_8 = "ftsri.php?get&exe" ascii //weight: 1
        $x_1_9 = "fsi.php?get&exe" ascii //weight: 1
        $x_1_10 = "mqkldrv" ascii //weight: 1
        $x_1_11 = "psaxlsl" ascii //weight: 1
        $x_1_12 = "allnewsmedia.webatu.com" ascii //weight: 1
        $x_1_13 = "lovecatalog.comlu.com" ascii //weight: 1
        $x_1_14 = "yourssagregator.comlu.com" ascii //weight: 1
        $x_1_15 = {31 d2 3b 5d 14 0f 9c c2 f7 da 21 da 8b 5d 10 0f b6 04 1a 8d 5a 01 f6 d8 30 04 31 41 39 f9 7c e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

rule Trojan_Win32_Agent_VDSK_2147744916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.VDSK!MTB"
        threat_id = "2147744916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4c 24 10 81 c2 dc 22 6e 01 89 11 8b cf 2b cd 03 c9 2b c8 81 c1 a9 77 00 00 89 15 ?? ?? ?? ?? 39 3d}  //weight: 2, accuracy: Low
        $x_2_2 = {66 8b 44 24 26 66 0b 44 24 26 8b 4c 24 10 66 89 44 24 26 8b 54 24 08 8a 1c 0a 8b 74 24 04 88 1c 0e}  //weight: 2, accuracy: High
        $x_2_3 = {81 ec 20 04 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 1c 04 00 00 81 3d ?? ?? ?? ?? 12 0f 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Agent_AG_2147745165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AG!MTB"
        threat_id = "2147745165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 e4 3b c7 73 77 8a 1c 18 80 f3 8f 8a c3 f6 d0 32 c3 24 0f 32 d8 8d 45 ef 88 5d ef 3b c1 73 34 3b f0 77 30 8b d8 2b de 3b ca 75 12 51 8d 4d d0 e8}  //weight: 1, accuracy: High
        $x_1_2 = ".tmp\" --ping" wide //weight: 1
        $x_1_3 = "\"%s\" start \"%s\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_PVD_2147745266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.PVD!MTB"
        threat_id = "2147745266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 74 24 1c 8b c1 83 44 24 1c 04 2b c3 2d 2f 16 00 00 0f b7 d8 8b 44 24 18 05 ?? ?? ?? ?? 83 6c 24 20 01 89 06}  //weight: 2, accuracy: Low
        $x_2_2 = {53 38 00 00 ba ?? ?? ?? ?? eb ?? 81 f2 ec f1 33 11}  //weight: 2, accuracy: Low
        $x_2_3 = {57 81 e9 3a 66 0d 77 01 ce 0c 00 32 81 ?? ?? ?? ?? 20 81}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Agent_AZ_2147787056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.AZ!MTB"
        threat_id = "2147787056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f d5 f7 29 d2 8d 04 f5 ?? ?? ?? ?? 20 c0 0f a5 d0 89 d0 0f a3 c5 f6 c7 07 83 c7 01 d0 f8 84 c3 8a 07 66 0f a3 cb f6 c6 03 ff 34 24 38 ed 84 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f9 66 0f ba e4 0d 66 ff c6 66 d3 ee 29 d9 66 c7 44 24 ?? 13 58 66 81 ee 0b 7b 0f b3 fe 8d 34 75 ?? ?? ?? ?? 8d 74 24 20 f5 83 ef 04 f5 ff 37 8f 44 24 1c f8 a8 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Agent_DM_2147788161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.DM!MTB"
        threat_id = "2147788161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 0a c0 e5 f3 66 0f ab d1 80 f1 cb 8b 4c 25 00 f8 81 c5 04 00 00 00 f9 33 cb}  //weight: 1, accuracy: High
        $x_1_2 = {01 6a 3d 2a bc f9 95 17 3c ed a5 95 30 9b 2a 1b 6a 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Agent_SA_2147789203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.SA"
        threat_id = "2147789203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_11_1 = "sagoge.com" ascii //weight: 11
        $x_11_2 = "macuwuf.com" ascii //weight: 11
        $x_1_3 = "bumblebee" ascii //weight: 1
        $x_1_4 = "pshell" ascii //weight: 1
        $x_1_5 = "/get_load" ascii //weight: 1
        $x_1_6 = "handshake" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_11_*) and 4 of ($x_1_*))) or
            ((2 of ($x_11_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Agent_RPJ_2147798589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.RPJ!MTB"
        threat_id = "2147798589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\Workspace\\Crypted\\a.pdb" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "wcfgmgr32.exe" ascii //weight: 1
        $x_1_4 = "lstrlenA" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
        $x_1_6 = "malloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agent_WTK_2147847400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agent.WTK!MTB"
        threat_id = "2147847400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stop-adw.txt" ascii //weight: 1
        $x_1_2 = "AdwTest.exe" ascii //weight: 1
        $x_1_3 = "m a bad mother fucker" ascii //weight: 1
        $x_1_4 = "Nobady can distroy me" ascii //weight: 1
        $x_1_5 = "You suck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

