rule PWS_Win32_Frethog_A_2147581999_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.A"
        threat_id = "2147581999"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows\\CurrentVersion\\RUN" ascii //weight: 1
        $x_2_2 = "AVP.Product_NotificatiOn" ascii //weight: 2
        $x_2_3 = "AVP.AlertDialoG" ascii //weight: 2
        $x_1_4 = "explorer.exe" ascii //weight: 1
        $x_2_5 = "%s %c%s%c%d" ascii //weight: 2
        $x_2_6 = {57 57 68 01 02 00 00 53 ff d6 57 57 68 02 02 00 00 53 ff d6}  //weight: 2, accuracy: High
        $x_2_7 = {c8 f0 d0 c7 d7 a2 b2 e1 b1 ed bc e0 bf d8 cc e1}  //weight: 2, accuracy: High
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "LoadResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_C_2147583439_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.C"
        threat_id = "2147583439"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "AVP.AlertDialog" ascii //weight: 5
        $x_5_2 = "EXE_WOW_EXE" ascii //weight: 5
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_5_4 = "DLL_WOW_DLL" ascii //weight: 5
        $x_5_5 = "JmpHookOn" ascii //weight: 5
        $x_1_6 = "JmpHookOff" ascii //weight: 1
        $x_1_7 = "Avenger by NhT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_B_2147583513_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.B"
        threat_id = "2147583513"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Windows\\CurrentVersion\\RUN" ascii //weight: 3
        $x_4_2 = "AVP.AlertDialoG" ascii //weight: 4
        $x_4_3 = {c8 f0 d0 c7 d7 a2 b2 e1 b1 ed bc e0 bf d8 cc e1}  //weight: 4, accuracy: High
        $x_3_4 = "%s %c%s%c%d" ascii //weight: 3
        $x_3_5 = "explorer.exe" ascii //weight: 3
        $x_3_6 = "WriteProcessMemory" ascii //weight: 3
        $x_2_7 = {57 57 68 01 02 00 00 53 ff d6 57 57 68 02 02 00 00 53 ff d6}  //weight: 2, accuracy: High
        $x_2_8 = {68 01 02 00 00 ?? ff d6 ?? ?? 68 02 02 00 00 ff 75 fc ff d6 68}  //weight: 2, accuracy: Low
        $x_1_9 = "LoadResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_G_2147584626_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.gen!G"
        threat_id = "2147584626"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_2 = "explorer.exe" ascii //weight: 1
        $x_3_3 = "RavMon" ascii //weight: 3
        $x_3_4 = "AlertDialog " ascii //weight: 3
        $x_8_5 = "config.wtf" ascii //weight: 8
        $x_8_6 = "realmList" ascii //weight: 8
        $x_30_7 = "SecurityMatrixFrame" ascii //weight: 30
        $x_30_8 = "%s?a=%s&s=%s&u=%s&p=%s&pin=%s&r=%s&l=%d&m=%d" ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 1 of ($x_8_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_30_*) and 1 of ($x_8_*) and 2 of ($x_3_*))) or
            ((1 of ($x_30_*) and 2 of ($x_8_*))) or
            ((2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_A_2147595041_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.A"
        threat_id = "2147595041"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%s?a=1&srv=%s&id=%s&" ascii //weight: 2
        $x_2_2 = "p=%s&s=%s&ss=%s&js=%s" ascii //weight: 2
        $x_2_3 = "&gj=%s&dj=%d&yz=%d" ascii //weight: 2
        $x_2_4 = {26 79 7a 3d 25 64 00 6b 65 72 6e 65 6c 33 32}  //weight: 2, accuracy: High
        $x_2_5 = "Forthgorr" ascii //weight: 2
        $x_1_6 = "OpenThread" ascii //weight: 1
        $x_2_7 = {54 68 72 65 61 64 00 00 73 65 72 76 65 72 6e 61}  //weight: 2, accuracy: High
        $x_1_8 = ".\\config.ini" ascii //weight: 1
        $x_2_9 = "%s?a=%d&s=%s&u=%s&p=%s&r=%s&l=%d&m=%d" ascii //weight: 2
        $x_2_10 = {77 73 32 5f c7 45}  //weight: 2, accuracy: High
        $x_2_11 = {49 73 44 65 c7 45}  //weight: 2, accuracy: High
        $x_2_12 = {00 10 41 3b c8 7c f5 68}  //weight: 2, accuracy: High
        $x_2_13 = {f9 e5 e5 e1 ab be be}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((9 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_F_2147595118_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.F"
        threat_id = "2147595118"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 73 3f 61 3d 25 73 26 73 3d 25 73 26 75 3d 25 73 26 70 3d 25 73 [0-32] 26 72 3d 25 73 26 6c 3d 25 (64|73) 26 6d 3d 25 (64|73)}  //weight: 10, accuracy: Low
        $x_5_2 = "WriteProcessMemory" ascii //weight: 5
        $x_5_3 = "ReadProcessMemory" ascii //weight: 5
        $x_5_4 = "SetWindowsHookExA" ascii //weight: 5
        $x_5_5 = "InternetOpenUrlA" ascii //weight: 5
        $x_2_6 = "Forthgoer" ascii //weight: 2
        $x_2_7 = "SeDebugPrivilege" ascii //weight: 2
        $x_2_8 = "gameclient.exe" ascii //weight: 2
        $x_2_9 = "soul.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_G_2147595141_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.G"
        threat_id = "2147595141"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 74 24 0c ff 74 24 0c ff 74 24 0c ff 35 ?? ?? 00 10 ff 15 ?? ?? 00 10 c2 0c 00 55 8b ec 81 ec 68 01 00 00 53 56 8d 45 9c 57 50 8d 45 b0 33 ff 50 c7 45 b0 6b 65 72 6e c7 45 b4 65 6c 33 32 c7 45 b8 2e 64 6c 6c 89 7d bc c7 45 9c 49 73 44 65 c7 45 a0 62 75 67 67 c7 45 a4 65 72 50 72 c7 45 a8 65 73 65 6e c7 45 ac 74 00 00 00 ff 15 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 ff d0 85 c0 74 07 c6 05 ?? ?? 00 10 01 8d 85 98 fe ff ff 68 03 01 00 00 50 57 ff 15 ?? ?? 00 10 8d 85 98 fe ff ff 6a 5c}  //weight: 1, accuracy: Low
        $x_1_2 = {67 61 6d 65 50 ?? c7 45 ?? 63 6c 69 65 c7 45 ?? 6e 74 2e 65 c7 45 ?? 78 65 00 00 ff d6}  //weight: 1, accuracy: Low
        $x_1_3 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_4 = "WINMM.dll" ascii //weight: 1
        $x_1_5 = ".\\setup\\default.Dat" ascii //weight: 1
        $x_1_6 = {49 73 44 65 c7 45 ?? 62 75 67 67 c7 45 ?? 65 72 50 72 c7 45 ?? 65 73 65 6e c7 45 ?? 74 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_Frethog_H_2147595142_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.H"
        threat_id = "2147595142"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 85 f6 74 67 33 ff 81 3e 23 fe 4e f7 8b 46 08 75 5a 85 c0 74 56 81 7e 0c 84 14 1a af 75 4d 83 c0 14 80 38 00 74 39 50 a1 ?? ?? 00 10 69 c0 04 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "%s?server=%s&gameid=%s&pass=%s&pin=%s&wupin=%s&role=%s&equ=%s&other=Build:%s" ascii //weight: 1
        $x_1_3 = "Forthgoner" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\\\update.ini" ascii //weight: 1
        $x_1_5 = "/post.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_I_2147595143_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.I"
        threat_id = "2147595143"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 53 55 56 57 50 6a 00 68 ff 0f 1f 00 ff 15 ?? ?? 00 10 8b d8 85 db 0f 84 97 00 00 00 68 ?? ?? 00 10 68 ?? ?? 00 10 ff 15 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 8b e8 83 c9 ff 8b 7c 24 18 33 c0 f2 ae f7 d1 49 6a 04 8b f1 68 00 10 00 00 46 56 50 53 ff 15 ?? ?? 00 10 8b f8 85 ff 74 50 85 f6 74 4c 8b 4c 24 18 6a 00 56 51 57 53 ff 15 ?? ?? 00 10 6a 00 6a 00 57 55 6a 00 6a 00 53 ff 15 ?? ?? 00 10 85 c0 74 1f 6a ff 50 ff 15 ?? ?? 00 10 68 00 80 00 00 6a 00 57 53 ff 15 ?? ?? 00 10 5f 5e 5d 5b c2 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = "GetWindowThreadProcessId" ascii //weight: 1
        $x_1_3 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_4 = "LookupPrivilegeValueA" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "CreateRemoteThread" ascii //weight: 1
        $x_1_7 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_8 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_9 = "InternetReadFile" ascii //weight: 1
        $x_1_10 = "OpenProcessToken" ascii //weight: 1
        $x_1_11 = "Explorer.exe" ascii //weight: 1
        $x_1_12 = "CreateThread" ascii //weight: 1
        $x_1_13 = "FindWindowA" ascii //weight: 1
        $x_1_14 = "OpenProcess" ascii //weight: 1
        $x_1_15 = "KillTimer" ascii //weight: 1
        $x_1_16 = "SetTimer" ascii //weight: 1
        $x_1_17 = "=%s&r=%s&l=%s&m" ascii //weight: 1
        $x_1_18 = "=%s&r=%s&l=%d&m" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (17 of ($x*))
}

rule PWS_Win32_Frethog_J_2147595277_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.J"
        threat_id = "2147595277"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 1c 01 00 00 53 56 57 33 db 89 5d e4 53 53 53 53 68 00 10 00 10 ff 15 ?? ?? 00 10 8b f8 89 7d e0 89 5d fc 3b fb 74 52 53 68 00 00 00 80 53 53 8b 45 08 50 57 ff 15 ?? ?? 00 10 8b f0 89 75 dc c7 45 fc 01 00 00 00 3b f3 74 27 8d 8d d4 fe ff ff 51 68 04 01 00 00 8d 95 d8 fe ff ff 52 56 ff 15 ?? ?? 00 10 85 c0 74 09 8d 85 d8 fe ff ff 89 45 e4 89 5d fc e8 14 00 00 00 c7 45 fc ff ff ff ff e8 13 00 00 00 eb 19 8b 7d e0 8b 75 dc}  //weight: 1, accuracy: Low
        $x_1_2 = {57 68 00 04 00 00 6a 40 ff 15 ?? ?? 00 10 89 45 e4 33 db 53 53 53 53 68 00 10 00 10 ff 15 ?? ?? 00 10 8b f8 89 7d dc 89 5d fc 3b fb 74 3f 53 68 00 00 00 80 53 53 8b 45 08 50 57 ff 15 ?? ?? 00 10 8b f0 89 75 e0 c7 45 fc 01 00 00 00 3b f3 74 14 8d 4d d8 51 68 00 04 00 00 8b 55 e4 52 56 ff 15 ?? ?? 00 10 89 5d fc e8 14 00 00 00 c7 45 fc ff ff ff ff e8 13 00 00 00 eb 19 8b 7d dc 8b 75 e0 56}  //weight: 1, accuracy: Low
        $x_1_3 = {64 89 25 00 00 00 00 81 ec 1c 01 00 00 53 56 57 33 ff 89 7d e4 57 57 57 57 68 00 ?? 00 10 ff 15 ?? ?? 00 10 89 45 e0 89 7d fc 3b c7 0f 84 88 00 00 00 57 68 00 00 00 80 57 57 8b 4d 08 51 50 ff 15 ?? ?? 00 10 8b f0 89 75 dc c7 45 fc 01 00 00 00 3b f7 74 5d 8d 95 d4 fe ff ff 52 68 04 01 00 00 8d 85 d8 fe ff ff 50 56 ff 15 ?? ?? 00 10 85 c0 74 3f}  //weight: 1, accuracy: Low
        $x_1_4 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_5 = "Explorer.exe" ascii //weight: 1
        $x_1_6 = {6c 69 6e 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_7 = "InternetOpenA" ascii //weight: 1
        $x_1_8 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_9 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule PWS_Win32_Frethog_A_2147595688_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.gen!A"
        threat_id = "2147595688"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2007"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {55 8b ec 83 ec 1c 8d 45 fc 50 6a 28 ff 15 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 85 c0 74 51 8d 45 f4 50 68 ?? ?? 00 10 6a 00 ff 15 ?? ?? 00 10 85 c0 74 33 8b 45 f4 6a 00 89 45 e8 8b 45 f8 89 45 ec 6a 00 8d 45 e4 6a 10 50 6a 00 ff 75 fc c7 45 e4 01 00 00 00 c7 45 f0 02 00 00 00 ff 15 ?? ?? 00 10 85 c0 75 09 ff 75 fc ff 15 ?? ?? 00 10 c9 c3}  //weight: 1000, accuracy: Low
        $x_1000_2 = {55 8b ec 51 8d 45 fc 56 50 6a 40 ff 75 14 8b 35 ?? ?? 00 10 ff 75 0c ff 75 08 ff d6 85 c0 74 2c 57 6a 00 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 ?? ?? 00 10 8b f8 8d 45 fc 50 ff 75 fc ff 75 14 ff 75 0c ff 75 08 ff d6 8b c7 5f 5e c9 c3}  //weight: 1000, accuracy: Low
        $x_1000_3 = {59 66 3d 6f 6b 74 ?? 66 3d 61 64 74 ?? 66 3d 75 70 74 ?? 66 3d 6e 6f 74 ?? 66 3d 74 72 74 ?? 66 3d 66 61 [0-6] c6 45 ff 01}  //weight: 1000, accuracy: Low
        $x_1_4 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_5 = "LookupPrivilegeValueA" ascii //weight: 1
        $x_1_6 = "GetCurrentProcess" ascii //weight: 1
        $x_1_7 = "OpenProcessToken" ascii //weight: 1
        $x_1_8 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "InternetReadFile" ascii //weight: 1
        $x_1_11 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1000_*) and 7 of ($x_1_*))) or
            ((3 of ($x_1000_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_B_2147595689_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.gen!B"
        threat_id = "2147595689"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "107"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Forthgoer" ascii //weight: 50
        $x_50_2 = "LaTaleClient.exe" ascii //weight: 50
        $x_50_3 = "gameclient.exe" ascii //weight: 50
        $x_50_4 = "Sungame.exe" ascii //weight: 50
        $x_50_5 = "ElementClient.exe" ascii //weight: 50
        $x_50_6 = "patchupdate.exe" ascii //weight: 50
        $x_50_7 = "cabalmain.exe" ascii //weight: 50
        $x_1_8 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_9 = "LookupPrivilegeValueA" ascii //weight: 1
        $x_1_10 = "GetCurrentProcess" ascii //weight: 1
        $x_1_11 = "OpenProcessToken" ascii //weight: 1
        $x_1_12 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_13 = "WriteProcessMemory" ascii //weight: 1
        $x_1_14 = "InternetReadFile" ascii //weight: 1
        $x_1_15 = "InternetOpenUrlA" ascii //weight: 1
        $n_500_16 = "ThunderSmartLimiter.exe" ascii //weight: -500
        $n_500_17 = "\\OverWolf.Client.BL\\obj\\x86\\Release\\OverWolf.Client.BL.pdb" ascii //weight: -500
        $n_500_18 = "Software\\Overwolf\\" wide //weight: -500
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_50_*) and 7 of ($x_1_*))) or
            ((3 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_K_2147595735_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.K"
        threat_id = "2147595735"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 79 73 74 65 6d 33 32 5c 6d 68 ?? ?? ?? 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {6c 69 6e 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_3 = "WinInet" ascii //weight: 1
        $x_1_4 = "explorer.exe" ascii //weight: 1
        $x_1_5 = "my.exe" ascii //weight: 1
        $x_1_6 = "WSGAME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_L_2147595742_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.L!dll"
        threat_id = "2147595742"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c0 83 3d ?? ?? 40 00 00 75 19 6a 00 a1 ?? ?? 40 00 50 68 ?? ?? 40 00 6a 03 e8 ?? ?? ?? ?? a3 ?? ?? 40 00 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {40 00 00 74 12 a1 ?? ?? 40 00 50 e8 ?? ?? ?? ?? 33 c0 a3 ?? ?? 40 00 c3}  //weight: 1, accuracy: Low
        $x_1_3 = "StartHook2" ascii //weight: 1
        $x_1_4 = "StopHook2" ascii //weight: 1
        $x_1_5 = "Hook.dll" ascii //weight: 1
        $x_1_6 = "Q360SafeMonClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_M_2147596158_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.M"
        threat_id = "2147596158"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 63 63 65 70 74 3a 20 2a 2f 2a 00 48 54 54 50 2f 31 2e 30 00 00 00 00 50 4f 53 54 00 00 00 00 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64}  //weight: 1, accuracy: High
        $x_1_2 = "wow.exe" ascii //weight: 1
        $x_1_3 = "W0W.exe" ascii //weight: 1
        $x_1_4 = "WQW.exe" ascii //weight: 1
        $x_1_5 = "WcW.exe" ascii //weight: 1
        $x_1_6 = "WaW.exe" ascii //weight: 1
        $x_1_7 = "JumpHookOn" ascii //weight: 1
        $x_1_8 = "Program Manager" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_N_2147596311_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.N"
        threat_id = "2147596311"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IZMteAKZG[GN\\t" ascii //weight: 1
        $x_1_2 = "AFLG_[tk]ZZMF\\~MZ[AGFtz}f" ascii //weight: 1
        $x_1_3 = "xZGL]K\\wfG\\ANAKI\\AGF" ascii //weight: 1
        $x_1_4 = "iDMZ\\lAIDGO" ascii //weight: 1
        $x_1_5 = "wzhengtu.dat" ascii //weight: 1
        $x_1_6 = "qqgame.exe" ascii //weight: 1
        $x_1_7 = "qq.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_N_2147596312_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.N"
        threat_id = "2147596312"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IZMteAKZG[GN\\t" ascii //weight: 1
        $x_1_2 = "AFLG_[tk]ZZMF\\~MZ[AGFtz}f" ascii //weight: 1
        $x_1_3 = "AVP.AlertDialog" ascii //weight: 1
        $x_1_4 = "AVP.Product_Notification" ascii //weight: 1
        $x_1_5 = "upxdnd.dll" ascii //weight: 1
        $x_1_6 = "51343281" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_N_2147596312_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.N"
        threat_id = "2147596312"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wzhengtu.dat" ascii //weight: 1
        $x_1_2 = "qqgame.exe" ascii //weight: 1
        $x_1_3 = "qq.exe" ascii //weight: 1
        $x_1_4 = "f=upt" ascii //weight: 1
        $x_1_5 = "f=not" ascii //weight: 1
        $x_1_6 = "f=trt" ascii //weight: 1
        $x_1_7 = "f=fat" ascii //weight: 1
        $x_1_8 = "CreateMutexA" ascii //weight: 1
        $x_1_9 = "%s?srv=%s&id=%s&p=%s&s=%s&ss=%s&js=%s&gj=%s&dj=%d&yz=%d&jz=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_O_2147596314_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.O"
        threat_id = "2147596314"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wow.exe" ascii //weight: 1
        $x_1_2 = "WO.DLL" ascii //weight: 1
        $x_1_3 = "WOW8-29" ascii //weight: 1
        $x_1_4 = "WoW.L" ascii //weight: 1
        $x_1_5 = "kav.X" ascii //weight: 1
        $x_1_6 = "antivirus.ex" ascii //weight: 1
        $x_1_7 = "fsav.exe" ascii //weight: 1
        $x_1_8 = "norton.eH" ascii //weight: 1
        $x_1_9 = "GetKeyboardType" ascii //weight: 1
        $x_1_10 = "csrss.exp" ascii //weight: 1
        $x_1_11 = "svchost.L" ascii //weight: 1
        $x_1_12 = "WTF\\Account" ascii //weight: 1
        $x_1_13 = "realmlist.wtf" ascii //weight: 1
        $x_1_14 = "SendARP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_O_2147596315_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.O"
        threat_id = "2147596315"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WO.DLL" ascii //weight: 1
        $x_1_2 = "IG.exe" ascii //weight: 1
        $x_1_3 = "WinSys" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_6 = "WTF\\Account" ascii //weight: 1
        $x_1_7 = "realmlist.wtf" ascii //weight: 1
        $x_1_8 = "set realmlist" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_P_2147596316_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.P"
        threat_id = "2147596316"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xyupri%d.dll" ascii //weight: 1
        $x_1_2 = "CZXSDERDAKSTXMH_MX" ascii //weight: 1
        $x_1_3 = "E3F426F6-42A5-A29E-8634-BC694A88FB7D" ascii //weight: 1
        $x_1_4 = "MNDLL" wide //weight: 1
        $x_1_5 = "RavMon.exe" ascii //weight: 1
        $x_1_6 = "AlertDialog" ascii //weight: 1
        $x_1_7 = "Product_Notification" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_P_2147596317_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.P"
        threat_id = "2147596317"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Extr rising hook MHTX000" ascii //weight: 1
        $x_1_2 = "E3F426F6-8634-42A5-A29E-BC694A88FB7D" ascii //weight: 1
        $x_1_3 = "CZXSDERDAKSTXMH_%d" ascii //weight: 1
        $x_1_4 = "Forthgoer" ascii //weight: 1
        $x_1_5 = "txotx.exe" ascii //weight: 1
        $x_1_6 = "mhmain.dll" ascii //weight: 1
        $x_1_7 = "WSGAME" ascii //weight: 1
        $x_1_8 = "gpwd_get_pwd_text" ascii //weight: 1
        $x_1_9 = "CallNextHookEx" ascii //weight: 1
        $x_1_10 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_S_2147596433_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.S"
        threat_id = "2147596433"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RCPT TO:<" ascii //weight: 1
        $x_1_2 = "MAIL FROM:<" ascii //weight: 1
        $x_1_3 = "HELO" ascii //weight: 1
        $x_2_4 = "g_hhook ==" ascii //weight: 2
        $x_2_5 = {6d 61 70 70 69 6e 67 00 00 43 61 6e 27 74 20 6d}  //weight: 2, accuracy: High
        $x_2_6 = {73 6d 74 70 00 00 00 00 74 63 70 00}  //weight: 2, accuracy: High
        $x_4_7 = "unest.net<mir" ascii //weight: 4
        $x_4_8 = "SetDIPSHook" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_T_2147596434_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.T"
        threat_id = "2147596434"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 6d 3d 25 64 00 46 6f 72 74 68 67 6f 65 72}  //weight: 1, accuracy: High
        $x_1_2 = {76 16 8b 45 08 8d 14 06 8b 5d 10 8a 04 0a 3a 04 19 75 05 41 3b cf 72 f0 3b cf 74 0d 46 3b 75 0c}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 f4 20 57 6e 64 c7 45 f8 43 6c 61 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_U_2147596577_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.U"
        threat_id = "2147596577"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vb6chs.dll" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "\\fonts\\Elephant.exe" wide //weight: 1
        $x_1_4 = "c:\\BOOT.INI" wide //weight: 1
        $x_1_5 = "c:\\ntldr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_U_2147596577_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.U"
        threat_id = "2147596577"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "InternetOpenUrlA" ascii //weight: 5
        $x_5_2 = "SetWindowsHookExA" ascii //weight: 5
        $x_5_3 = "WriteProcessMemory" ascii //weight: 5
        $x_5_4 = "ReadProcessMemory" ascii //weight: 5
        $x_5_5 = "CreateToolhelp32Snapshot" ascii //weight: 5
        $x_2_6 = "del \"" ascii //weight: 2
        $x_2_7 = "if exist \"" ascii //weight: 2
        $x_2_8 = "\" goto Loop" ascii //weight: 2
        $x_2_9 = "del %0" ascii //weight: 2
        $x_2_10 = "SendGameData" ascii //weight: 2
        $x_1_11 = "QQLogin.exe" ascii //weight: 1
        $x_1_12 = "ini\\GameSetUp.ini" ascii //weight: 1
        $x_1_13 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_14 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" ascii //weight: 1
        $x_1_15 = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" ascii //weight: 1
        $x_1_16 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" ascii //weight: 1
        $x_1_17 = "rsmyapm.dll" ascii //weight: 1
        $x_1_18 = "rsmybpm.dll" ascii //weight: 1
        $x_1_19 = "rsmycpm.dll" ascii //weight: 1
        $x_1_20 = "rsmyafg.dll" ascii //weight: 1
        $x_1_21 = "rsmyamp.dll" ascii //weight: 1
        $x_1_22 = "play.exe" ascii //weight: 1
        $x_1_23 = "soul.exe" ascii //weight: 1
        $x_1_24 = "Main.dll" ascii //weight: 1
        $x_1_25 = "EnHookWindow" ascii //weight: 1
        $x_1_26 = "SkipFireWall" ascii //weight: 1
        $x_1_27 = "UnHookWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 4 of ($x_2_*) and 17 of ($x_1_*))) or
            ((3 of ($x_5_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_5_*) and 4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((5 of ($x_5_*) and 15 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((5 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((5 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_X_2147596687_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.X"
        threat_id = "2147596687"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ElementClient.exe" ascii //weight: 1
        $x_1_2 = "w2i.com.cn" ascii //weight: 1
        $x_1_3 = "CRACKING" ascii //weight: 1
        $x_1_4 = "mibao.asp" ascii //weight: 1
        $x_1_5 = "CallNextHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_S_2147596914_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.S"
        threat_id = "2147596914"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "myapp.exe /c del \"C:\\myapp.exe\"" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\NetMeeting\\ravytmon.cfg" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\NetMeeting\\ravytmon.exe" ascii //weight: 1
        $x_1_4 = "avp.exe" ascii //weight: 1
        $x_1_5 = "zhengtu.dat" ascii //weight: 1
        $x_1_6 = "MZKERNEL32.DLL" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "strrchr" ascii //weight: 1
        $x_1_10 = "AVP.TrafficMonConnectionTerm" ascii //weight: 1
        $x_1_11 = "AVP.Product_Notification" ascii //weight: 1
        $x_1_12 = "AVP.AlertDialog" ascii //weight: 1
        $x_1_13 = "AVP.Button" ascii //weight: 1
        $x_1_14 = "#32770" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (13 of ($x*))
}

rule PWS_Win32_Frethog_Y_2147596927_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.Y"
        threat_id = "2147596927"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zhengtu.dat" ascii //weight: 1
        $x_1_2 = "gameclient.exe" ascii //weight: 1
        $x_1_3 = "LaTaPS" ascii //weight: 1
        $x_1_4 = "IZMteAKZG[GN\\t" ascii //weight: 1
        $x_1_5 = "AFLG_[tk]ZZMF\\~MZ[AGFtz}f" ascii //weight: 1
        $x_1_6 = "xZGL]K\\wfG\\ANAKI\\AGF" ascii //weight: 1
        $x_1_7 = "iDMZ\\lAIDGO" ascii //weight: 1
        $x_1_8 = "CallNextHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_F_2147596932_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.gen!F"
        threat_id = "2147596932"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 64 2e 64 6c 6c 00 00 00 00 59 55 54 44 46 47 48 4b 48 43 4f 4f 4c 57 57 5f}  //weight: 5, accuracy: High
        $x_5_2 = {25 64 2e 64 6c 6c 00 00 00 00 50 41 53 44 45 52 51 52 53 41 45 45 41 53 41 5f}  //weight: 5, accuracy: High
        $x_20_3 = {64 11 40 00 58 11 40 00 46 69 6c 4d 73 67 2e 65 78 65 00 00 54 77 69 73 74 65 72 2e 65 78 65 00 ?? ?? 53 6f 62 6a 45 76 65 6e 74 4e 61 6d 65 00 ?? ?? 44 6c 6c 4d 6f 64 75 6c 65 4e 61 6d 65 00 ?? ?? 45 78 65 4d 6f 64 75 6c 65 4e 61 6d 65 00}  //weight: 20, accuracy: Low
        $x_1_4 = "RavMon.exe" ascii //weight: 1
        $x_1_5 = "AVP.AlertDialog" ascii //weight: 1
        $x_1_6 = "WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_AA_2147596952_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AA"
        threat_id = "2147596952"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 83 ec 20 53 56 8d 45 e0 57 50 c7 45 e0 4c 6f 67 69 c7 45 e4 6e 43 74 72 c7 45 e8 6c 2e 64 6c c7 45 ec 6c 00 00 00 ff 15 4c 40 00 10 8b d8 85 db 89 5d f4 74 17 bf 00 00 50 00 57 6a 00 ff 15 04 40 00 10 8b f0 85 f6 89 75 f0 75 07 32 c0 e9 b2 00 00 00 56 ff 15 00 40 00 10 89 75 fc c7 45 f8 00 05 00 00 29 5d fc be 00 10 00 00 8b 45 fc 6a 00 03 c3 56 50 53 ff 35 0c 5a 00 10 ff 15 48 40 00 10}  //weight: 10, accuracy: High
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_G_2147597162_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.gen!G"
        threat_id = "2147597162"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "131"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 5c 65 6c 65 6d 65 6e 74 63 6c 69 65 6e 74 2e 65 78 65}  //weight: 100, accuracy: High
        $x_10_2 = "http://aspx.vod38.com/" ascii //weight: 10
        $x_10_3 = "http://aspx.qqus.net/wanmei/login.asp" ascii //weight: 10
        $x_10_4 = {7b 41 45 42 36 37 31 37 45 2d 37 45 31 39 2d 31 31 64 30 2d 39 37 45 45 2d 30 30 43 30 34 46 44 39 31 39 37 ?? 7d}  //weight: 10, accuracy: Low
        $x_10_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 10
        $x_1_6 = "tpRequest" ascii //weight: 1
        $x_1_7 = "%ssetcodvalue.asp?username=%s&c=%s%s%s" ascii //weight: 1
        $x_1_8 = "%ssetstatus.asp?username=%s&s=" ascii //weight: 1
        $x_1_9 = "%s?u=%s&p=%s&cp=%s&s=%s&n=%s&l=%d&v=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_H_2147597251_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.gen!H"
        threat_id = "2147597251"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 03 01 00 00 50 56 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 6a 5c 50 ff 15 ?? ?? ?? ?? 8b f8 8d 45 f4 50 c7 45 f4 7a 68 65 6e 8d 5f 01 c7 45 f8 67 74 75 2e 53 c7 45 fc 64 61 74 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_H_2147597251_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.gen!H"
        threat_id = "2147597251"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "960"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "RavMon.exe" ascii //weight: 100
        $x_100_2 = "OpenProcessToken" ascii //weight: 100
        $x_100_3 = "SeDebugPrivilege" ascii //weight: 100
        $x_100_4 = "AdjustTokenPrivileges" ascii //weight: 100
        $x_100_5 = "LookupPrivilegeValueA" ascii //weight: 100
        $x_100_6 = "CreateToolhelp32Snapshot" ascii //weight: 100
        $x_100_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 100
        $x_50_8 = "winlog0n.exe" ascii //weight: 50
        $x_50_9 = "explorer.exe" ascii //weight: 50
        $x_50_10 = "FilMsg.exe" ascii //weight: 50
        $x_50_11 = "Twister.exe" ascii //weight: 50
        $x_50_12 = "VC20XC00U" ascii //weight: 50
        $x_50_13 = "AVP.Alert" ascii //weight: 50
        $x_50_14 = "AVP.Product" ascii //weight: 50
        $x_50_15 = "AlertDialog" ascii //weight: 50
        $x_50_16 = "Product_Notification" ascii //weight: 50
        $x_10_17 = "WinExec" ascii //weight: 10
        $x_10_18 = "InternetOpen" ascii //weight: 10
        $x_10_19 = "CallNextHookEx" ascii //weight: 10
        $x_10_20 = "VirtualAllocEx" ascii //weight: 10
        $x_10_21 = "SetWindowsHookExA" ascii //weight: 10
        $x_10_22 = "ReadProcessMemory" ascii //weight: 10
        $x_10_23 = "CreateRemoteThread" ascii //weight: 10
        $x_10_24 = "WriteProcessMemory" ascii //weight: 10
        $n_500_25 = "is registered trademark of Kaspersky Lab." wide //weight: -500
        $n_500_26 = "qqkav: loaded" ascii //weight: -500
        $n_1000_27 = "ggsafe.com/ggtools.ini" ascii //weight: -1000
        $n_1000_28 = "AnVir Task Manager" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((5 of ($x_100_*) and 8 of ($x_50_*) and 6 of ($x_10_*))) or
            ((5 of ($x_100_*) and 9 of ($x_50_*) and 1 of ($x_10_*))) or
            ((6 of ($x_100_*) and 6 of ($x_50_*) and 6 of ($x_10_*))) or
            ((6 of ($x_100_*) and 7 of ($x_50_*) and 1 of ($x_10_*))) or
            ((6 of ($x_100_*) and 8 of ($x_50_*))) or
            ((7 of ($x_100_*) and 4 of ($x_50_*) and 6 of ($x_10_*))) or
            ((7 of ($x_100_*) and 5 of ($x_50_*) and 1 of ($x_10_*))) or
            ((7 of ($x_100_*) and 6 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_AB_2147597356_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AB"
        threat_id = "2147597356"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_2 = "08E909A4-48DD-8BCC-B236-90A604B93E68" ascii //weight: 10
        $x_10_3 = "RavMon.exe" ascii //weight: 10
        $x_10_4 = "AVP.AlertDialog" ascii //weight: 10
        $x_10_5 = "#32770" ascii //weight: 10
        $x_1_6 = "Forthgoer" ascii //weight: 1
        $x_1_7 = "tldoor%d.dll" ascii //weight: 1
        $x_1_8 = "FilMsg.exe" ascii //weight: 1
        $x_1_9 = "Twister.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_AC_2147599154_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AC"
        threat_id = "2147599154"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 08 0b c0 75 1d e8 ?? ?? ?? ?? 0b c0 74 14 6a 00 6a 04 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8}  //weight: 2, accuracy: Low
        $x_1_2 = "ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_AD_2147599155_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AD"
        threat_id = "2147599155"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 eb 02 8b 4d 14 33 d2 8b 04 96 41 83 e1 1f d3 c0 33 c7 89 04 96 42 3b d3 75 ed 61 5f 5e 5b 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_AE_2147599156_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AE"
        threat_id = "2147599156"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 83 c4 04 85 c0 74 15 6a 01 e8 ?? ?? 00 00 83 c4 04 68 98 3a 00 00 ff 15 ?? ?? 40 00 6a 00 6a 00 6a 00 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_AF_2147599157_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AF"
        threat_id = "2147599157"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 c6 04 10 e9 8b cb 2b c8 83 e9 05 89 4c 10 01 c6 03 e9 8b 45 0c 2b c3 83 e8 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_AH_2147600617_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AH"
        threat_id = "2147600617"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/ff11mail/" ascii //weight: 2
        $x_1_2 = "\\usr\\all\\login_w" ascii //weight: 1
        $x_1_3 = "mouse WinText:" ascii //weight: 1
        $x_1_4 = "haha:bmp" ascii //weight: 1
        $x_1_5 = "&passmem=" ascii //weight: 1
        $x_1_6 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_7 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_AI_2147601010_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AI"
        threat_id = "2147601010"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 69 6e 74 72 6f 3d 00 26 75 72 6c 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 4e 75 6d 00 45 6e 74 65 72}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 0a 00 64 61 74 61 5c}  //weight: 1, accuracy: High
        $x_2_4 = {3b c2 7e 79 81 c1 1e 02 00 00 3b c1 7d 6f 8d 45 fc 50 56}  //weight: 2, accuracy: High
        $x_3_5 = {6a 04 50 68 b4 5e f7 01 57 ff d6}  //weight: 3, accuracy: High
        $x_3_6 = {6a 04 50 68 94 56 f7 01 57 ff d6 8d 45 10 50 6a 14 68}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_I_2147601754_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.gen!I"
        threat_id = "2147601754"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {74 f2 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 86 e0 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 38 e0}  //weight: 3, accuracy: High
        $x_1_2 = "Product_Notifica" ascii //weight: 1
        $x_2_3 = {41 6c 65 72 74 44 69 61 6c 6f 67 00 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 2, accuracy: High
        $x_2_4 = {23 33 32 37 37 30 00 00 52 61 76 4d 6f 6e 2e 65 78 65}  //weight: 2, accuracy: High
        $x_1_5 = "CurrentVersion\\Run" ascii //weight: 1
        $x_2_6 = "rundl132.exe" ascii //weight: 2
        $x_2_7 = {b9 07 00 00 00 33 c0 8d 7c 24 0d c6 44 24 0c 00 f3 ab 66 ab aa}  //weight: 2, accuracy: High
        $x_2_8 = {46 3b f7 8a 04 03 88 44 34 0b 7c ec 8d 7c 24 0c}  //weight: 2, accuracy: High
        $x_1_9 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_10 = "TerminateProcess" ascii //weight: 1
        $x_1_11 = "CreateRemoteThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_AK_2147602109_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AK"
        threat_id = "2147602109"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 05 10 00 00 eb 0c be 04 10 00 00 eb 05 be 08 10 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 68 02 00 01 20 56 ff 75 08 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8d 45 e8 50 c7 45 e8 18 00 00 00 ff 75 08 c7 45 f4 01 00 00 00 c7 45 f8 94 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {6a 01 68 01 02 00 00 56 ff d7 53 53 68 02 02 00 00 56}  //weight: 1, accuracy: High
        $x_1_5 = {53 53 6a 10 50 ff d7 6a 32 ff 15}  //weight: 1, accuracy: High
        $x_1_6 = "#32770" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_Frethog_AL_2147602286_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AL"
        threat_id = "2147602286"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WriteProcessMemory" ascii //weight: 1
        $x_5_2 = {8b 44 24 04 03 c1 80 30 ?? 41 3b 4c 24 08 7c f0}  //weight: 5, accuracy: Low
        $x_3_3 = "=%s&srv=%s&id1=%s&dj1=%s&pc=%s" ascii //weight: 3
        $x_5_4 = {8b 4d 14 33 d2 8b 04 96 41 83 e1 1f d3 c0 33 c7 89 04 96 42 3b d3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_AO_2147605604_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AO"
        threat_id = "2147605604"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 2a 66 8b 45 ec 66 3b 45 dc 75 19 66 8b 45 ee 66 3b 45 de 75 0f 0f b7 45 e2 0f b7 4d f2 2b c8 83 f9 ?? 7c 07}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 50 68 2b e0 22 00 ff 75 08 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_AO_2147605658_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AO!sys"
        threat_id = "2147605658"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {81 7d 20 2b e0 22 00 75 47 83 7d 14 04 73 12 c7 06 0d 00 00 c0 c7 46 04 00 00 00 00 e9}  //weight: 5, accuracy: High
        $x_4_2 = {83 4d d0 ff c7 45 cc 90 9b f7 ff 6a 00 6a 37 ff 75 d0 ff 75 cc 8d 45 d4 50 e8}  //weight: 4, accuracy: High
        $x_10_3 = {74 25 8b 75 10 ff 37 8f 06 50 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 58 89 07 50 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 58}  //weight: 10, accuracy: High
        $x_1_4 = {55 8b ec b8 0d 00 00 c0 c9 c2 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_R_2147605756_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.R"
        threat_id = "2147605756"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "CreateToolhelp32Snapshot" ascii //weight: 20
        $x_2_2 = "RavMon.exe" ascii //weight: 2
        $x_2_3 = "qqdoor%d.dll" ascii //weight: 2
        $x_1_4 = "Product_Notification" ascii //weight: 1
        $x_1_5 = "AlertDialog" ascii //weight: 1
        $x_1_6 = "FilMsg.exe" ascii //weight: 1
        $x_1_7 = "Twister.exe" ascii //weight: 1
        $x_1_8 = "D64AC2E4-40DD-90D9-95B1-0C60F7CA64BF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_AP_2147606947_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AP"
        threat_id = "2147606947"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 00 28 00 00 53 89 08 c7 40 04 c8 00 00 00 c7 40 08 44 18 00 00 ff 15 ?? ?? ?? ?? 5b c3 56 8b 74 24 08 6a 01 56 ff 15 ?? ?? ?? ?? 85 c0 75 3f 81 3e 7a 6f 6e 67 75}  //weight: 2, accuracy: Low
        $x_1_2 = {7e 18 8b 54 24 0c 53 8b ce 2b d6 8b f8 8a 1c 0a 80 f3 ?? 88 19 41 48 75 f4 5b 80 24 37 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 7d f9 c6 45 f8 e9 b9 ?? ?? ?? ?? ab a1 ?? ?? ?? ?? 6a 05 2b c8 5e 2b ce 56}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 f0 4c 6f 67 69 c7 45 f4 6e 5f 53 65 c7 45 f8 72 76 65 72 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_J_2147606994_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.gen!J"
        threat_id = "2147606994"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {60 e8 00 00 00 00 58 b9}  //weight: 3, accuracy: High
        $x_3_2 = {72 6f 6c 65 3d 00 [0-16] 70 69 6e 3d}  //weight: 3, accuracy: Low
        $x_2_3 = {58 61 81 c7 a0 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {67 61 6d 65 69 64 3d 00 [0-4] 26}  //weight: 2, accuracy: Low
        $x_2_5 = "Accept-Language: zh-cn" ascii //weight: 2
        $x_2_6 = "PasswordDlg" ascii //weight: 2
        $x_1_7 = "trojankiller" ascii //weight: 1
        $x_1_8 = "HttpQ" ascii //weight: 1
        $x_1_9 = "zhengtu" ascii //weight: 1
        $x_1_10 = "CurrentControlSet\\Control\\Session" ascii //weight: 1
        $x_1_11 = "Hook" ascii //weight: 1
        $x_1_12 = "WriteProcessMemory" ascii //weight: 1
        $x_1_13 = "VirtualProtectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_AG_2147606997_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AG"
        threat_id = "2147606997"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 68 6f 6f 6b 20 64 6c 6c 20 72 69 73 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 43 4c 53 49 44 5c 4e 4f 44 33 32 4b 56 42 49 54 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d 14 8b 55 10 c7 00 1f 00 00 00 56 8b 01 03 c2 0f b6 50 03 0f b6 70 02 c1 e2 08 03 d6 0f b6 70 01 0f b6 00 c1 e2 08 03 d6 5e c1 e2 08 03 d0 8b 45 08 89 10 83 01 04 8b 00 c1 e8 1f 5d c2 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_AU_2147607002_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AU"
        threat_id = "2147607002"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {6a fb 58 2b 46 04 6a 05 01 06 8d 46 ff 50 ff 76 04 53 e8 ?? ?? ?? ?? 8b 46 04 83 c4 10 83 c0 05 01 06 83 c6 09 4f}  //weight: 4, accuracy: Low
        $x_1_2 = {46 6f 72 74 68 67 6f 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = "b=%s&c=%s&e=%s&f=%s&h=%s&k=%s&l=%s&m=%s&n=%u&s=%d&q=%s" ascii //weight: 1
        $x_1_4 = {78 79 6d 61 69 6e 2e 62 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_AW_2147607004_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AW"
        threat_id = "2147607004"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Forthgoer" ascii //weight: 10
        $x_1_2 = "%s\\dllcache\\%s.jpg" ascii //weight: 1
        $x_1_3 = "%s?act=getpos&d10=%s&pos=&d80=" ascii //weight: 1
        $x_1_4 = "mibao.asp" ascii //weight: 1
        $x_1_5 = "zhengtu.dat" ascii //weight: 1
        $x_1_6 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_7 = {73 71 6d 6d 61 69 6c 00 73 71 6d 69 6d 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_AZ_2147607007_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.AZ"
        threat_id = "2147607007"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 67 6f 6c 64 70 61 73 73 3d 00 00 26 73 61 76 65 70 61 73 73 3d 00 00 26 73 61 76 69 6e 67 73 3d 00 00 00 26 6d 6f 6e 65 79 3d 00 26 6c 65 76 65 6c 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = "gameclient.exe" ascii //weight: 1
        $x_1_3 = {6c 69 6e 2e 61 73 70 00 75 70 66 69 6c 65 2e 61 73 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_BL_2147607019_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.BL"
        threat_id = "2147607019"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 32 c6 06 25 46 0f b6 07 50 8d 45 ?? 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 66 8b 45}  //weight: 2, accuracy: Low
        $x_2_2 = {c6 07 e8 2b c7 83 e8 05 89 47 01 8a 45 0b 3c 68 88 47 05 74 0e 3c a3 74 0a}  //weight: 2, accuracy: High
        $x_2_3 = {2b f7 89 47 06 83 ee 0a c6 47 0a e9 89 77 0b 5f 5e}  //weight: 2, accuracy: High
        $x_1_4 = "%s\\dllcache\\%s.jpg" ascii //weight: 1
        $x_1_5 = "mibao.asp" ascii //weight: 1
        $x_1_6 = "%s?act=getpos&d10=%s&pos=&d80=" ascii //weight: 1
        $x_1_7 = "%s%s%s-%d.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_BM_2147607020_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.BM"
        threat_id = "2147607020"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "account=%s&password1=%s&password2=%s&specialSign=%s&cash=%d&client=" ascii //weight: 1
        $x_1_2 = "&server=%s&inputsource=%s&levels=%d&name=%s&other=%s&verify=%s" ascii //weight: 1
        $x_1_3 = "mibao.asp" ascii //weight: 1
        $x_1_4 = "act=getpos&account=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_BN_2147607021_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.BN"
        threat_id = "2147607021"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?act=getover&account=" ascii //weight: 1
        $x_1_2 = "elementclient.exe" ascii //weight: 1
        $x_1_3 = "\\Data\\id.ini" ascii //weight: 1
        $x_1_4 = "?act=getpos&account=%s" ascii //weight: 1
        $x_1_5 = "server=%s&account=%s&password1=%s&ProtPass=%s&Verify=%s" ascii //weight: 1
        $x_1_6 = "%s?s=%s" ascii //weight: 1
        $x_1_7 = "?act=getthmbok&account=" ascii //weight: 1
        $x_1_8 = "\\userdata\\currentserver.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule PWS_Win32_Frethog_BP_2147607023_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.BP"
        threat_id = "2147607023"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 68 61 76 65 6d 69 62 61 6f 3d 00 26 70 61 73 73 77 6f 72 64 32 3d 00 26 6d 6f 6e 65 79 3d 00 26 6c 65 76 65 6c}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\WINDOWS\\dnf.ini" ascii //weight: 1
        $x_1_3 = {6c 69 6e 2e 61 73 70 00 75 70 66 69 6c 65 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {6d c6 44 24 ?? 69 c6 44 24 ?? 62 c6 44 24 ?? 6f c6 44 24 ?? 3d 88 5c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Frethog_BR_2147607025_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.BR"
        threat_id = "2147607025"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 6c 65 6d 65 6e 74 63 6c 69 65 6e 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {5f 5f 5f 5f 41 56 50 2e 52 6f 6f 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 08 85 c0 74 ?? 6a 02 56 ff d7 8b f0 85 f6 75 d2 5f 8b c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_BS_2147607026_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.BS"
        threat_id = "2147607026"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 68 66 [0-6] 2e 64 6c 4c}  //weight: 1, accuracy: Low
        $x_1_2 = {4b 52 5f 44 4c 4c 2e 64 6c 6c 00 47 4f 4f 44 42 4f 59}  //weight: 1, accuracy: High
        $x_1_3 = "sbanner=yes&loginname=df" ascii //weight: 1
        $x_1_4 = {00 64 6e 66 2e 65 78 65 00 45 72 72 6f 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_BU_2147607028_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.BU"
        threat_id = "2147607028"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad\\" ascii //weight: 10
        $x_10_2 = "regsvr32.exe /s " ascii //weight: 10
        $x_1_3 = "%s&Name=%s&Pass=%s&role=%s&Level=%s&Money=%s" ascii //weight: 1
        $x_1_4 = "=%s&PassRole=%s&MB=%s&Card=%s=%s|%s=%s|%s=%s&Store=%s&Key=%s&" ascii //weight: 1
        $x_1_5 = "?action=getpos&Name=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_BW_2147607030_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.BW"
        threat_id = "2147607030"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 64 6c 6c 00 48 6f 6f 6b 4f 66 66 00 48 6f 6f 6b 4f 6e}  //weight: 10, accuracy: High
        $x_10_2 = {41 63 63 65 70 74 3a 20 2a 2f 2a 00 48 54 54 50 2f 31 2e 30}  //weight: 10, accuracy: High
        $x_1_3 = "/chd/sendmail.asp" ascii //weight: 1
        $x_1_4 = "inf\\DllAddress.ini" ascii //weight: 1
        $x_1_5 = {53 65 72 76 3d [0-15] 43 61 6e 6b 3d [0-15] 4c 65 76 65 3d [0-15] 4e 61 6d 65 3d}  //weight: 1, accuracy: Low
        $x_1_6 = {4d 69 62 61 6f 3d [0-15] 43 68 61 6e 67 3d [0-15] 44 69 61 6e 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_BY_2147607032_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.BY"
        threat_id = "2147607032"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41}  //weight: 2, accuracy: High
        $x_1_2 = {51 54 6a 01 6a 00 68 e1 fa ed 0e}  //weight: 1, accuracy: High
        $x_1_3 = {8b d8 6a 32 8d 45 ?? 50 53 e8 ?? ?? ff ff 8d 4d fc}  //weight: 1, accuracy: Low
        $x_3_4 = {7e 1e bf 01 00 00 00 8b 5d fc 8b 45 f8 e8 ?? ?? ?? ff 8a 13 80 f2 ?? 88 54 38 ff 47 43 4e 75 ea}  //weight: 3, accuracy: Low
        $x_3_5 = {8b 45 f0 80 7c 18 fa e8 75 ?? 8b 45 f0 80 7c 18 f2 c6}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_BZ_2147607033_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.BZ"
        threat_id = "2147607033"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "516"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "xyupri%d.dll" ascii //weight: 100
        $x_100_2 = "E3F426F6-42A5-A29E-8634-BC694A88FB7D" ascii //weight: 100
        $x_100_3 = {00 6d 79 2e 65 78 65}  //weight: 100, accuracy: High
        $x_100_4 = "FilMsg.exe" ascii //weight: 100
        $x_100_5 = "Twister.exe" ascii //weight: 100
        $x_10_6 = "RavMon.exe" ascii //weight: 10
        $x_5_7 = "MNDLL" ascii //weight: 5
        $x_5_8 = "#32770" ascii //weight: 5
        $x_5_9 = "Process32Next" ascii //weight: 5
        $x_5_10 = "Process32First" ascii //weight: 5
        $x_5_11 = "CreateToolhelp32Snapshot" ascii //weight: 5
        $x_1_12 = "ExeModuleName" ascii //weight: 1
        $x_1_13 = "DllModuleName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_100_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((5 of ($x_100_*) and 4 of ($x_5_*))) or
            ((5 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((5 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_CA_2147607034_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.CA"
        threat_id = "2147607034"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_2 = {33 c9 39 4c 24 08 7e 10 8b 44 24 04 03 c1 80 30 ?? 41 3b 4c 24 08 7c f0 c3}  //weight: 10, accuracy: Low
        $x_10_3 = {c6 45 f0 5d c6 45 f1 4a c6 45 f2 4c c6 45 f3 32 c6 45 f4 5d c6 45 f5 70 c6 45 f6 79}  //weight: 10, accuracy: High
        $x_4_4 = {00 36 36 39 37 31 38 33 35 00}  //weight: 4, accuracy: High
        $x_3_5 = {57 90 90 90 90 90 90}  //weight: 3, accuracy: High
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "CreateRemoteThread" ascii //weight: 1
        $x_1_8 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\RUN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_CB_2147607035_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.CB"
        threat_id = "2147607035"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 71 6c 6f 67 69 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "%s?act=getpos&d10=%s&pos=&d80=%d" ascii //weight: 1
        $x_1_3 = {8a 07 c6 07 e9 8b 4f 01 89 4d 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_GF_2147607143_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.GF"
        threat_id = "2147607143"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Forthgoer" ascii //weight: 10
        $x_10_2 = "http://23drf.com/xmfx" ascii //weight: 10
        $x_10_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_4 = "System\\CurrentControlSet\\Services\\" ascii //weight: 10
        $x_1_5 = "avast.setup" ascii //weight: 1
        $x_1_6 = "AVP.EXE" ascii //weight: 1
        $x_1_7 = "prupdate.ppl" ascii //weight: 1
        $x_1_8 = "AYUpdate.aye" ascii //weight: 1
        $x_1_9 = "PlayOnline ID" ascii //weight: 1
        $x_1_10 = "pol.exe" ascii //weight: 1
        $x_1_11 = "polcore.dll" ascii //weight: 1
        $x_1_12 = "maplestory.exe" ascii //weight: 1
        $x_1_13 = "ageofconan.exe" ascii //weight: 1
        $x_1_14 = "lotroclient.exe" ascii //weight: 1
        $x_1_15 = "turbinelauncher.exe" ascii //weight: 1
        $x_1_16 = "wow.exe" ascii //weight: 1
        $x_1_17 = "cabalmain.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_K_2147607409_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.gen!K"
        threat_id = "2147607409"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 eb 02 8b 4d 14 33 d2 90 8b 04 96 90 41 83 e1 1f d3 c0 33 c7 89 04 96 42 3b d3 75 eb 61 5f 5e 5b 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_MK_2147607586_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MK"
        threat_id = "2147607586"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 63 f3 ab 13 00 c6 85 ?? ?? ?? ?? 61 c6 85 ?? ?? ?? ?? 62 c6 85}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 77 54 50 ff 55 40 ff d0}  //weight: 1, accuracy: High
        $x_1_3 = {73 76 63 68 6f 73 74 2e 64 6c 6c 00 41 52 00 47 65 74 56 65 72 00 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Frethog_MK_2147607586_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MK"
        threat_id = "2147607586"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 4b e1 22 00 ff 75 08 ff 15 ?? ?? ?? ?? 85 c0 74 0f ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {66 70 69 64 c7 45 ?? 73 64 6f 73 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {66 81 7d fc e8 e8 74 0c 46 83 fe 05 7c bf}  //weight: 1, accuracy: High
        $x_1_4 = {74 46 56 be ?? ?? ?? ?? ff 36 8d 85 fc fe ff ff 50 ff 15 ?? ?? ?? ?? 59 85 c0 59 74 0d}  //weight: 1, accuracy: Low
        $x_1_5 = {73 22 2b 08 8d 45 e0 50 ff 75 f0 03 4d e4 ff 75 08 89 4d e0 e8 ?? ?? ?? ?? 83 c4 0c 83 c6 04 ff 45 f0 eb cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_ML_2147607587_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.ML"
        threat_id = "2147607587"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 eb 02 8b 4d 14 33 d2 8b 04 96 41 83 e1 1f d3 c0 33 c7 90 89 04 96 42 3b d3 75 ec 61 5f 5e 5b}  //weight: 2, accuracy: High
        $x_1_2 = {8b c8 31 11 83 c1 04 81 f9 ?? ?? ?? ?? 72 f3 53 56 57 6a 01 68 12 f8 33 c6}  //weight: 1, accuracy: Low
        $x_1_3 = {8a d1 32 d0 3a cb 88 17 74 05 40 3b c6 72 e5 33 c0 8a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_MM_2147609731_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MM"
        threat_id = "2147609731"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 1a 68 ff ff 00 00 e8 ?? ?? ff ff a1 ?? ?? ?? ?? 50 e8 ?? ?? ff ff 84 db 0f 85 ?? ?? 00 00 6a 00 6a 00 6a 03 6a 00 6a 01 68 00 00 00 40 8d 45 e4}  //weight: 1, accuracy: Low
        $x_2_2 = {8b d8 83 fb ff 74 ?? 6a 00 6a 00 68 c0 c8 50 00 53 e8 ?? ?? ff ff b8}  //weight: 2, accuracy: Low
        $x_1_3 = {77 6f 77 2e 65 78 65 00 57 4f 57 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 6f 6f 6b 6f 6e 00 00 48 6f 6f 6b 6f 66 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_MM_2147609732_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MM!dll"
        threat_id = "2147609732"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8a 0c 10 80 c1 88 80 f1 77 80 e9 88 88 0c 10 42 81 fa 11 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 04 03 e9 40 8b ca c1 e9 00 80 e1 ff 88 0c 03 40 8b ca c1 e9 08 80 e1 ff 88 0c 03 40 8b ca c1 e9 10 80 e1 ff 88 0c 03 40 c1 ea 18}  //weight: 1, accuracy: High
        $x_1_3 = {b8 c0 e2 c6 00 44 b8 c1 e2}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 02 6a 00 68 ef fe ff ff 53 e8 ?? ?? ff ff 6a 00 68 ?? ?? 40 00 68 11 01 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = "game.DoPatch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Frethog_MO_2147618080_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MO"
        threat_id = "2147618080"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {50 44 4c 4c 2e 64 6c 6c 00 48 6f 6f 6b 6f 66 66 00 48 6f 6f 6b 6f 6e 00 00}  //weight: 10, accuracy: High
        $x_5_2 = "elementclient.exe" ascii //weight: 5
        $x_1_3 = "action=up&zt=" ascii //weight: 1
        $x_1_4 = {69 73 6f 6e 6c 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {6e 6f 72 65 73 70 6f 6e 64 00}  //weight: 1, accuracy: High
        $x_1_6 = "/flash.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_NM_2147619310_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.NM"
        threat_id = "2147619310"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 64 6e 66 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "sbanner=yes&loginname=df" ascii //weight: 1
        $x_1_3 = "sed.drauGemaG" ascii //weight: 1
        $x_1_4 = "GOODBOY" ascii //weight: 1
        $x_10_5 = {68 22 74 af 00 68 22 74 a0 00 e8 ?? ?? 00 00 6a 06 68 ?? ?? 00 10 68 ?? ?? 00 10 68 3c 94 cf 00 68 3c 94 a9 00 e8 ?? ?? 00 00 6a 13 68 ?? ?? 00 10 68 ?? ?? 00 10 68 5a 45 b3 00 68 1a 68 a0 00 e8 ?? ?? 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_MK_2147624670_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MK!dll"
        threat_id = "2147624670"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&hiddenFile=&coffer.ascx%3AtxtAmount=" ascii //weight: 1
        $x_1_2 = "FenGame Set" ascii //weight: 1
        $x_10_3 = {8b c3 6a 05 99 59 f7 f9 85 d2 75 ?? 8a 45 10 8a 0c 37 d0 e0 2a c8 88 0e eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_MQ_2147638983_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MQ"
        threat_id = "2147638983"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 6e 66 63 c7 45 ?? 68 69 6e 61 c7 45 ?? 2e 65 78 65 c7 45 ?? 71 71 6c 6f c7 45 ?? 67 69 6e 2e c7 45 ?? 64 6e 66 2e}  //weight: 2, accuracy: Low
        $x_1_2 = {83 7d fc 03 0f 85 ?? ?? ?? ?? 80 65 ?? 00 81 7d ?? 47 49 46 00 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = {74 12 8b 45 ?? 81 38 23 23 23 23 75 07}  //weight: 1, accuracy: Low
        $x_1_4 = {74 29 56 ff 15 ?? ?? ?? ?? 83 f8 03 75 0b 56 ff 75 ?? e8 ?? ?? ?? ?? 59 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_MR_2147639317_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MR"
        threat_id = "2147639317"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {78 f8 ff ff e9 0d 00 2b ?? 83 ?? 05 89 ?? 74 f8 ff ff c6 85}  //weight: 5, accuracy: Low
        $x_5_2 = {c7 85 70 f8 ff ff 20 00 00 e0}  //weight: 5, accuracy: High
        $x_2_3 = {b8 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_4 = {68 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_1_5 = {25 73 5c 77 69 6e 5f 25 64 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 44 52 5f 44 4c 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_MR_2147639317_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MR"
        threat_id = "2147639317"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {53 8a 1c 08 80 f3 ?? 88 1c 08 40 3b c2 72 f2}  //weight: 3, accuracy: Low
        $x_1_2 = "%s:\\Program Files\\Common Files\\%s" ascii //weight: 1
        $x_1_3 = {5c 73 79 73 74 65 6d 53 65 74 55 70 2e 69 6e 66 [0-5] 25 63 25 73 25 63 [0-5] 5c 72 75 6e 2e 62 61 74}  //weight: 1, accuracy: Low
        $x_1_4 = "%s?n=%s&p=%s&l=%s" ascii //weight: 1
        $x_1_5 = {4a 4d 56 5f 56 4d 4a 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 69 6e 69 [0-5] 54 53 53 61 66 65 45 64 69 74 2e 64 61 74 [0-5] 4c 6f 67 69 6e 43 74 72 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_MR_2147639498_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MR!dll"
        threat_id = "2147639498"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 39 8b 4c 24 0c c6 00 60 2b c8 c6 40 01 54 83 e9 07 c6 40 02 e8 89 48 03 c6 40 07 61 c6 40 08 68 8b 56 01 50 56 8d 4c 32 05 c6 40 0d c3}  //weight: 5, accuracy: High
        $x_2_2 = {2b c8 83 e9 05 6a 05 89 [0-10] c6 [0-3] e9}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 4c 24 18 8d 74 04 1c 8a 14 2e 32 d1 40 3b c7 88 16 72 ec}  //weight: 2, accuracy: High
        $x_1_4 = "Glbkvlt_evt_0001" ascii //weight: 1
        $x_1_5 = "game_loginfo.log" ascii //weight: 1
        $x_1_6 = "BeanPass" ascii //weight: 1
        $x_1_7 = "YAHOOJST+HOST:%s+IP:%s+USERID:%s+PASS:%s+Ver:%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_MS_2147639544_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MS"
        threat_id = "2147639544"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c 03 c1 80 30 86 41 3b cf 72}  //weight: 1, accuracy: High
        $x_1_2 = {80 38 e9 74 11 6a 05}  //weight: 1, accuracy: High
        $x_1_3 = {46 6f 72 74 68 67 6f 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_2147639968_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MT"
        threat_id = "2147639968"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "TFuckNOD" ascii //weight: 4
        $x_2_2 = "MiniSnifferClass" ascii //weight: 2
        $x_2_3 = "Unit_ZTFun" ascii //weight: 2
        $x_3_4 = "KNTMSP-LLK34Z1TABD" ascii //weight: 3
        $x_1_5 = "MAIL FROM: <" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_MV_2147640559_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.MV"
        threat_id = "2147640559"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 23 23 23 23 75}  //weight: 1, accuracy: High
        $x_1_2 = {8d 0c 38 83 ea 05 5f 83 c0 05 c6 01 e9 89 51 01}  //weight: 1, accuracy: High
        $x_1_3 = {81 3c 39 eb 02 aa aa 0f 84 ?? ?? ?? ?? 8d 04 92 6a 28 53 8d bc c6 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {80 7d 0b bf 76 06 80 7d 0b c4 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Frethog_NE_2147647944_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.NE"
        threat_id = "2147647944"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#Lock#Security#=" ascii //weight: 1
        $x_1_2 = "uid=%d&zid=%d&cid=%d&gid=%s&token=%s" ascii //weight: 1
        $x_1_3 = "&processb=%s&process=%s" ascii //weight: 1
        $x_1_4 = "xhtml.php?token=0xABCD" ascii //weight: 1
        $x_2_5 = {8d 3c 02 33 f7 2b ce 8b 75 ec 81 c2 47 86 c8 61 85 f6 7f bd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Frethog_NF_2147654103_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.NF"
        threat_id = "2147654103"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eXplOrER.Exe" ascii //weight: 1
        $x_1_2 = "\\cURRENTcONTROLsET\\sERVICES\\" ascii //weight: 1
        $x_1_3 = "%s:\\Program Files\\Common Files\\%s" ascii //weight: 1
        $x_1_4 = {5c 53 65 74 55 70 2e 69 6e 66 00 00 25 63 25 73 25 63 00 00 5c 72 75 6e 2e 62 61 74}  //weight: 1, accuracy: High
        $x_1_5 = "%s?n=%s&p=%s&l=%s" ascii //weight: 1
        $x_1_6 = "JMV_VMJ" ascii //weight: 1
        $x_1_7 = {54 53 53 61 66 65 45 64 69 74 2e 64 61 74 00 00 4c 6f 67 69 6e 43 74 72 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Frethog_NL_2147688493_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Frethog.NL"
        threat_id = "2147688493"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\MvuijhKz.exe" ascii //weight: 10
        $x_10_2 = ".woai310.com/?do=post&u=%s&m=%s&c=%d&s=%d&r=%s&v=%s&p=%s" ascii //weight: 10
        $x_1_3 = "fifa07.exe" ascii //weight: 1
        $x_1_4 = "gta3.exe" ascii //weight: 1
        $x_1_5 = "left4dead.exe" ascii //weight: 1
        $x_1_6 = "nba2k10.exe" ascii //weight: 1
        $x_1_7 = "wow.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

