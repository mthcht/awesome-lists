rule Backdoor_Win32_Bifrose_2147487759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose"
        threat_id = "2147487759"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\iexplore.exe" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" ascii //weight: 1
        $x_1_5 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_6 = "capCreateCaptureWindowA" ascii //weight: 1
        $x_1_7 = "SHGetSpecialFolderPathA" ascii //weight: 1
        $x_1_8 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_9 = "CreateRemoteThread" ascii //weight: 1
        $x_1_10 = "WriteProcessMemory" ascii //weight: 1
        $x_1_11 = "WNetEnumResourceA" ascii //weight: 1
        $x_1_12 = "POP3 Password" ascii //weight: 1
        $x_1_13 = "HTTPMail Password" ascii //weight: 1
        $x_1_14 = {48 6f 74 6d 61 69 6c 00 48 54 54 50 4d 61 69 6c 20 55 73 65 72 20 4e 61 6d 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_A_2147573995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.gen!A"
        threat_id = "2147573995"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {55 8b ec 56 33 f6 39 75 0c 7e 1b 8b 45 08 33 d2 8d 0c 06 8b c6 f7 75 14 8b 45 10 8a 04 02 30 01 46 3b 75 0c 7c e5 5e 5d c3}  //weight: 3, accuracy: High
        $x_2_2 = {6b 69 78 4b 7a 6d 69 7c 6d 4b 69 78 7c 7d 7a 6d 5f 71 76 6c 77 7f 49}  //weight: 2, accuracy: High
        $x_2_3 = "MvijtmI}|wlqit" ascii //weight: 2
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = {53 4f 46 54 57 41 52 45 5c 57 47 65 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 74 75 62 70 61 74 68 00}  //weight: 1, accuracy: High
        $x_1_7 = {70 6c 75 67 69 6e 31 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_8 = "capCreateCaptureWindowA" ascii //weight: 1
        $x_1_9 = "%c%d.%d.%d.%d|%s|%s|%s|%s|%s|%u|%i|%i|%u|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bifrose_B_2147573996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.gen!B"
        threat_id = "2147573996"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Norse Mythology, Bifrost Bridge" ascii //weight: 1
        $x_1_2 = "guardian is the god Heimdall." ascii //weight: 1
        $x_1_3 = "Listening on port %1!" ascii //weight: 1
        $x_1_4 = "uccessfully killed process" ascii //weight: 1
        $x_1_5 = {3c 52 61 6d 64 69 73 6b 3e 00 00 00 3c 52 65 6d}  //weight: 1, accuracy: High
        $x_1_6 = "\\BIFROST\\B" ascii //weight: 1
        $x_1_7 = "McAfee Antivirus" ascii //weight: 1
        $x_1_8 = "avgcc32.exe" ascii //weight: 1
        $x_1_9 = "PestPatrol.exe" ascii //weight: 1
        $x_1_10 = "Nvcc.exe" ascii //weight: 1
        $x_1_11 = "InoRpc.exe" ascii //weight: 1
        $x_1_12 = "%d kb of" ascii //weight: 1
        $x_1_13 = "Dns/IP 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_Win32_Bifrose_DN_2147575925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.DN"
        threat_id = "2147575925"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 a3 ?? ?? 40 00 8b 0d ?? ?? 40 00 3b 0d ?? ?? 40 00 7e 0c 8b 15 ?? ?? 40 00 89 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6b d2 09 03 c2 33 d2 be e8 03 00 00 f7 f6 2b ca 89 4d fc 83 7d f8 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 94 02 00 00 8b 0d ?? ?? 40 00 51 68 94 02 00 00 8b 95 ?? ?? ?? ?? 52 8b 45 ?? 03 05 ?? ?? 40 00 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_EF_2147593591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.EF"
        threat_id = "2147593591"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "rgMwF.gfCteNH" wide //weight: 10
        $x_10_2 = "llehS.tpircSW" wide //weight: 10
        $x_10_3 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS\\UCKH" wide //weight: 10
        $x_1_4 = "VB5!6&VB6ES.DLL" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_C_2147597852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.gen!C"
        threat_id = "2147597852"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_9_1 = {55 8b ec 56 33 f6 39 75 0c 7e 1b 8b 45 08 33 d2 8d 0c 06 8b c6 f7 75 14 8b 45 10 8a 04 02 30 01 46 3b 75 0c 7c e5 5e 5d}  //weight: 9, accuracy: High
        $x_3_2 = {50 89 b5 80 fa ff ff 89 75 e4 89 bd 78 fa ff ff c7 85 7c fa ff ff ?? ?? ?? ?? c7 85 84 fa ff ff ?? ?? ?? ?? ff d7}  //weight: 3, accuracy: Low
        $x_3_3 = "wins.sys" ascii //weight: 3
        $x_1_4 = "<Left Windows key DOWN>" ascii //weight: 1
        $x_1_5 = "HTTPMail Password2" ascii //weight: 1
        $x_1_6 = "MSN Explorer Signup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_9_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bifrose_D_2147598147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.gen!D"
        threat_id = "2147598147"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 74 75 62 70 61 74 68 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 6c 75 67 69 6e 31 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 4f 46 54 57 41 52 45 5c 57 67 65 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
        $x_2_6 = {6b 69 78 4b 7a 6d 69 7c 6d 4b 69 78 7c 7d 7a 6d 5f 71 76 6c 77 7f 49}  //weight: 2, accuracy: High
        $x_2_7 = {70 69 66 00 73 63 72 00 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_8 = {c6 85 d7 fc ff ff 03 e9 83 00 00 00 83 bd 84 fe ff ff 04 75 7a 83 bd 88 fe ff ff 0a 75 09 c6 85 d7 fc ff ff 02}  //weight: 2, accuracy: High
        $x_100_9 = {f7 75 14 8b 45 10 8a 04 02 30 01 [0-4] 46 3b 75 0c 7c 15 00 [0-11] 8b 45 08 (31|33) d2 8d 0c 06 (89 f0|8b c6)}  //weight: 100, accuracy: Low
        $x_100_10 = {57 8b 7c 24 0c 33 c9 85 ff 7e 28 53 8b 5c 24 18 55 8b 6c 24 18 56 8b 74 24 14 8b c1 33 d2 f7 f3 8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf 7c ea}  //weight: 100, accuracy: High
        $x_100_11 = {85 c0 0f 84 d4 f4 ff ff 68 f4 01 00 00 ff 15 ?? ?? ?? ?? 8b 85 ?? ?? ff ff 50 b9 02 01 00 00 81 ec ?? ?? 00 00 8d b5 ?? ?? ff ff 8b fc f3 a5 e8}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bifrose_AE_2147600018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.AE"
        threat_id = "2147600018"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Users\\7MooDi\\Desktop\\S\\Project1.vbp" wide //weight: 1
        $x_1_2 = "C0nv3Rt" ascii //weight: 1
        $x_1_3 = {43 00 3c 00 72 ?? ?? ?? 65 ?? ?? ?? 61 ?? ?? ?? 74 ?? ?? ?? 65 ?? ?? ?? 50 ?? ?? ?? 72 ?? ?? ?? 6f ?? ?? ?? 63 ?? ?? ?? 65 ?? ?? ?? 73 ?? ?? ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_AE_2147600018_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.AE"
        threat_id = "2147600018"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\iexplore.exe" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\%s" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" ascii //weight: 1
        $x_1_5 = "Bifrost Remote Controller" ascii //weight: 1
        $x_1_6 = "capGetDriverDescriptionA" ascii //weight: 1
        $x_1_7 = "capCreateCaptureWindowA" ascii //weight: 1
        $x_1_8 = "ZwWriteVirtualMemory" ascii //weight: 1
        $x_1_9 = "CreateRemoteThread" ascii //weight: 1
        $x_1_10 = "InternetReadFile" ascii //weight: 1
        $x_1_11 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_12 = "ZwCreateThread" ascii //weight: 1
        $x_1_13 = "torShutdown" ascii //weight: 1
        $x_1_14 = "umxtray.exe" ascii //weight: 1
        $x_1_15 = "kavsvc.exe" ascii //weight: 1
        $x_1_16 = "IsNTAdmin" ascii //weight: 1
        $x_1_17 = "torWrite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (16 of ($x*))
}

rule Backdoor_Win32_Bifrose_EY_2147604940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.EY"
        threat_id = "2147604940"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 ca 41 f7 d1 [0-10] 80 80 30 10 40 00 ?? 40 3d 00 60 00 00 72 d9}  //weight: 1, accuracy: Low
        $x_1_2 = {56 33 f6 39 75 0b ?? 1b 8b 45 08 33 d2 8d 0c 06 8b c6 f7 75 14 8b 45 10 ?? 04 02 30 01 46 3b 75 0c 7c e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Bifrose_P_2147605876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.P"
        threat_id = "2147605876"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 45 00 00 4c 01 02 00 76 f8 a5 46 00 00 00 00 00 00 00 00 e0 00 0f 01 0b 01 06 00 00 68 00 00 00 30 00 00 00 00 00 00 19 77 00 00 00 10 00 00 00 80 00 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 b0 00 00 00 04 00 00 78 44 01 00 02 00 00 00 00 00 10 00 00 10 00 00 00 00 10 00 00 10 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 f0 76 00 00 3c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {27 27 27 48 33 30 29 31 cc 0e 5f af b3 91 2b ba 4d 09 27 27 32 7f 27 27 27 ed 27 27 4d 2c 27 9b 02 c8 c9 b7 27 47 9a 5f 7a 26 26 26 26 76 6d 7b 7e 68 79 6c 83 74 90 8a 99 96 9a 96 8d 9b 83 68}  //weight: 1, accuracy: High
        $x_1_3 = {2e 74 65 78 74 00 00 00 f2 67 00 00 00 10 00 00 00 68 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 e0 2e 72 73 72 63 00 00 00 30 2e 00 00 00 80 00 00 00 30 00 00 00 6c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40}  //weight: 1, accuracy: High
        $x_1_4 = {0a 8b 94 fe e5 5e bd 65 aa 4c 31 27 58 34 38 a3 6c ff 01 22 43 ba 3e 51 b7 6e 80 91 02 26 32 06 45 ef 81 1d e8 de 31 f8 10 a8 18 47 aa df 14 12 29 30 71 23 08 e6 ac 9c 8d 3c 48 b0 33 a9 67 64 2c a3 fd ea df ea d8 06 9c 19 e7 63 c5 93 78 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_FI_2147609849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.FI"
        threat_id = "2147609849"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "141"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {59 0f b7 11 89 04 3a 66 83 79 02 00 74 ?? 0f b7 51 02 03 c2 83 c1 04 eb}  //weight: 100, accuracy: Low
        $x_10_2 = "WiN.eXe" ascii //weight: 10
        $x_10_3 = "msnmsgr.exe" ascii //weight: 10
        $x_10_4 = "softwaRe\\cLassEs\\HttP\\Shell\\Open\\command" ascii //weight: 10
        $x_10_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_1_6 = "bing.no-ip.biz" ascii //weight: 1
        $x_1_7 = "diddy69.no-ip.org" ascii //weight: 1
        $x_1_8 = "{DC6B213B-751A-185C-22B8-738F809CB05F}" ascii //weight: 1
        $x_1_9 = "{9B71D88C-C598-4935-C5D1-43AA4DB90836}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bifrose_E_2147610584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.gen!E"
        threat_id = "2147610584"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 31 d2 8d 0c 07 89 f8 f7 75 14 8b 45 10 8a 04 02 25 ff 00 00 00 31 01 47 3b 7d 0c 7c e0}  //weight: 1, accuracy: High
        $x_1_2 = {6a 04 50 57 ff d6 81 75 ?? 68 a7 62 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_FT_2147616633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.FT"
        threat_id = "2147616633"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {99 f7 f9 8a 82 ?? ?? ?? 00 8a 54 1f ff 32 c2 5a 88 02 43 4e 75}  //weight: 10, accuracy: Low
        $x_10_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_3 = "\\Program Files\\Messenger\\msnmsgs.exe" ascii //weight: 10
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_6 = "SeDebugPrivilege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bifrose_FU_2147616891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.FU"
        threat_id = "2147616891"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Bifrost" ascii //weight: 10
        $x_10_2 = {73 74 75 62 70 61 74 68 00}  //weight: 10, accuracy: High
        $x_10_3 = "NtWriteVirtualMemory" ascii //weight: 10
        $x_10_4 = "{9B71D88C-C598-4935-C5D1-43AA4DB90836}" ascii //weight: 10
        $x_10_5 = "%c%d.%d.%d.%d|%s|%s|%s|%s|%s|%u|%i|%i|%u|" ascii //weight: 10
        $x_1_6 = "SOFTWARE\\Microsoet\\Active Setup\\Installed Components\\%s" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoet\\Windows\\CurrentVersion\\App Paths\\iexplore.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bifrose_HM_2147627731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.HM"
        threat_id = "2147627731"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Bifrost Remote Controller" ascii //weight: 1
        $x_1_2 = "%c%u|%u|%u|%u|%u|" ascii //weight: 1
        $x_1_3 = "<%u-%.2u-%.2u %.2u:%.2u><%s>" ascii //weight: 1
        $x_1_4 = {6b 61 76 73 76 63 2e 65 78 65 00 ?? 6b 61 76 2e 65 78 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_HH_2147630933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.HH"
        threat_id = "2147630933"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 00 ce 10 68 ?? ?? ?? ?? 68 27 00 00 00 68 00 01 00 00 68 c8 00 00 00 68 c2 01 00 00 68 00 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {50 68 01 00 00 00 ff 74 24 10 68 01 68 00 00 ff 74 24 14}  //weight: 1, accuracy: High
        $x_1_3 = "CF#%^36grr5tthnbey" ascii //weight: 1
        $x_1_4 = {36 42 36 35 37 32 36 45 36 35 36 43 33 33 33 32 32 45 36 34 36 43 36 43 00 34 45 37 34 35 35 36 45 36 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_HO_2147631240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.HO"
        threat_id = "2147631240"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateProcessA" ascii //weight: 1
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "RtlMoveMemory" ascii //weight: 1
        $x_2_4 = "hidden Content. LuisN2" wide //weight: 2
        $x_2_5 = "Indetectables Online" ascii //weight: 2
        $x_2_6 = "zixnnj11u01rhuwda18gc5003tr97s9w2p850j0cj5mborrzyh4532" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bifrose_HR_2147632479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.HR"
        threat_id = "2147632479"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {41 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 61 00 64 00 64 00 79 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 56 00 69 00 73 00 75 00 61 00 6c 00 20 00 42 00 61 00 73 00 69 00 63 00 20 00 36 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 73 00 5c 00 46 00 55 00 44 00 20 00 90 00 72 00 79 00 70 00 74 00 65 00 72 00 5c 00 73 00 74 00 75 00 62 00 2e 00 76 00 62 00 70 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_F_2147632603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.gen!F"
        threat_id = "2147632603"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Portions Copyright (c) 1999,2003 Avenger by NhT" ascii //weight: 1
        $x_3_2 = "ap0calypse" ascii //weight: 3
        $x_3_3 = "YuklenenDizin" ascii //weight: 3
        $x_2_4 = "Injecsiyon" ascii //weight: 2
        $x_1_5 = "DisableSafeMode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bifrose_HU_2147636737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.HU"
        threat_id = "2147636737"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {75 08 3c 36 74 2c 34 36 eb 25}  //weight: 3, accuracy: High
        $x_1_2 = {66 c7 44 24 18 d4 07 66 c7 44 24 1a 08 00 66 c7 44 24 1e 11 00 66 c7 44 24 20 14 00}  //weight: 1, accuracy: High
        $x_2_3 = {75 09 66 81 7c 30 fe c7 05 74 15}  //weight: 2, accuracy: High
        $x_1_4 = "?action=updated&hostid" ascii //weight: 1
        $x_1_5 = "%s\\config\\%snt.dl" ascii //weight: 1
        $x_1_6 = "netsvcs_0x%d" ascii //weight: 1
        $x_1_7 = "Reset_SSDT" ascii //weight: 1
        $x_1_8 = "Global\\NetPass" ascii //weight: 1
        $x_1_9 = "\\\\.\\RESS_DTDOS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bifrose_IC_2147643669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.IC"
        threat_id = "2147643669"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 77 61 6d 70 5c 77 77 77 5c [0-32] 5c 53 74 75 62 5c 52 65 6c 65 61 73 65 5c 73 74 75 62 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 4d 5a 00 00 66 39 01 74 04 33 c0 c9 c3 8b 41 3c 03 c1 81 38 50 45 00 00 75 ef 83 65 fc 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_IH_2147646125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.IH"
        threat_id = "2147646125"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 80 30 66 41 3b 4d ec 72 ef}  //weight: 1, accuracy: High
        $x_1_2 = {80 7d 84 e8 74 07 c7 45 b4 90 90 90 90}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 d4 6a 80 4d d5 ff c6 45 d6 e8}  //weight: 1, accuracy: High
        $x_1_4 = {59 59 8d 8d e4 fe ff ff 49 49 c6 04 08 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Bifrose_IN_2147653876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.IN"
        threat_id = "2147653876"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 76 69 65 77 50 72 6f 63 65 73 73 2e 6a 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 61 64 64 52 65 67 69 74 65 6d 2e 68 74 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 f5 3e eb 04 c6 45 f5 3f 0f b6 45 f6 83 f8 40 7e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_IO_2147654050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.IO"
        threat_id = "2147654050"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\monstermo nst ermonste\\monstermonste\\rmonstermo\\nsterm ons\\termonstermons.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_IQ_2147654348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.IQ"
        threat_id = "2147654348"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 14 c7 00 68 00 00 00 90 a1 ?? ?? ?? ?? c7 40 01 ?? ?? ?? ?? 90 ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {80 34 03 f3 ff d7 50 ff d6 8b 45 fc 80 34 03 c2 ff d7 50 ff d6 8b 45 fc 80 34 03 d4 43 3b 5d f8 72 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_IQ_2147654348_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.IQ"
        threat_id = "2147654348"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 00 69 00 66 00 31 00 32 00 33 00 00 00 00 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "2CBE016A-8F28-4E0C-83A6-6079161294D7" wide //weight: 1
        $x_1_3 = {43 00 61 00 63 00 68 00 65 00 4d 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 74 00 75 00 62 00 50 00 61 00 74 00 68 00 00 00 00 00 63 00 61 00 63 00 68 00 65 00 00 00 2f 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 00 63 00 3a 00 5c 00 2a 00 00 00 25 00 63 00 3a 00 5c 00 25 00 73 00 00 00 00 00 2e 00 65 00 78 00 65 00 00 00 00 00 2d 00 61 00 78 00 00 00 20 00 00 00 2d 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_CB_2147818040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.CB!MTB"
        threat_id = "2147818040"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\temp\\virus.exe" ascii //weight: 1
        $x_1_2 = "temp2.exe" ascii //weight: 1
        $x_1_3 = "temp1.doc" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bifrose_ABF_2147895117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bifrose.ABF!MTB"
        threat_id = "2147895117"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e0 33 d2 52 50 8b c3 c1 e0 03 8d 04 80 99 03 04 24 13 54 24 04 83 c4 08 8b 55 fc 03 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

