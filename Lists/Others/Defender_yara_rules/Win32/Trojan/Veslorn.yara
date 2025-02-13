rule Trojan_Win32_Veslorn_A_2147597038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Veslorn.gen!A"
        threat_id = "2147597038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Veslorn"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 44 24 31 02 66 89 7c 24 36 88 4c 24 54 88 44 24 55 bd ?? ?? ?? ?? eb 02 33 ff ff d3 99 b9 fa 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 4c 24 14 6a 10 51 6a 00 52 68 ?? ?? 00 10 57 ff ?? 4e 75 ?? 83 3d ?? ?? 00 10 01 75 ?? 5d 5b 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 4c 24 14 6a 10 51 6a 00 52 68 ?? ?? 00 10 57 ff d5 4e 75 e1 83 3d ?? ?? 00 10 01 75 cb 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Veslorn_A_2147602206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Veslorn.A"
        threat_id = "2147602206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Veslorn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\SVCH0ST.EXE" ascii //weight: 10
        $x_10_2 = "[Autorun]" ascii //weight: 10
        $x_10_3 = "open=%s" ascii //weight: 10
        $x_10_4 = "shellexecute=%s" ascii //weight: 10
        $x_10_5 = "shell\\1=Open" ascii //weight: 10
        $x_10_6 = "CreateRemoteThread" ascii //weight: 10
        $x_10_7 = "WriteProcessMemory" ascii //weight: 10
        $x_10_8 = "SeDebugPrivilege" ascii //weight: 10
        $x_10_9 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_10 = "AdjustTokenPrivileges" ascii //weight: 10
        $x_1_11 = "RavmonD.exe" ascii //weight: 1
        $x_1_12 = "Ravmon.exe" ascii //weight: 1
        $x_1_13 = "kavsvc.exe" ascii //weight: 1
        $x_1_14 = "avp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Veslorn_B_2147608966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Veslorn.gen!B"
        threat_id = "2147608966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Veslorn"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "143"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {8b 44 24 04 66 81 38 4d 5a 75 ?? 8b 48 3c 03 c1 81 38 50 45 00 00 75}  //weight: 100, accuracy: Low
        $x_10_2 = "\\xcopy.exe" ascii //weight: 10
        $x_10_3 = "ServiceDLL" ascii //weight: 10
        $x_10_4 = ".\\RESSDTDOS" ascii //weight: 10
        $x_10_5 = "%SystemRoot%\\System32\\BFDDos.dll" ascii //weight: 10
        $x_1_6 = "CreateRemoteThread" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_9 = "NtQuerySystemInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Veslorn_C_2147608977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Veslorn.gen!C"
        threat_id = "2147608977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Veslorn"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 04 52 68 4b e1 22 00 50 ff 15 ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_10_2 = {57 33 32 54 69 6d 65 00 20 3e 20 6e 75 6c 00 00 20 2f 63 20 64 65 6c 20 00 00 00 00 43 4f 4d 53 50 45 43 00 5c 78 63 6f 70 79 2e 65 78 65 00 00}  //weight: 10, accuracy: High
        $x_2_3 = {00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 57 33 32 54 69 6d 65 5c 50 61 72 61 6d 65 74 65 72 73 00}  //weight: 2, accuracy: High
        $x_2_4 = {00 5c 5c 2e 5c 52 45 53 53 44 54 44 4f 53 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 00}  //weight: 2, accuracy: High
        $x_2_6 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 00}  //weight: 2, accuracy: High
        $x_2_7 = {00 43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 00}  //weight: 2, accuracy: High
        $x_2_8 = {00 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Veslorn_D_2147617548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Veslorn.D"
        threat_id = "2147617548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Veslorn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 65 72 76 00 b9 a4 b3 cc 31 00 00 44 6f 77 6e 4c 6f 61 64 65 72 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "||RavmonD.exe||RavStub.exe||KVXP.exe||KvMonXP.exe||KVCenter.exe||" wide //weight: 1
        $x_1_3 = "http://congs.zziyuan.com/1.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Veslorn_D_2147619805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Veslorn.gen!D"
        threat_id = "2147619805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Veslorn"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 42 46 44 44 4f 53 2f 25 64 2d 25 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 46 59 48 48 4f 53 3d 25 64 2b 25 64 28 4d 42 29 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 46 59 59 4c 43 53 3d 25 64 2b 25 64 28 4d 42 29}  //weight: 1, accuracy: High
        $x_5_4 = {00 41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e 0d 0a}  //weight: 5, accuracy: High
        $x_5_5 = "ATTACK" ascii //weight: 5
        $x_5_6 = {00 52 45 54 55 52 4e 50 4f 57 45 52}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Veslorn_E_2147619806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Veslorn.gen!E"
        threat_id = "2147619806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Veslorn"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 72 b0 65 88 4c 24 02 88 4c 24 06}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 0d 62 88 44 24 0e 88 44 24 0f c6 44 24 10 70 c6 44 24 11 2e 88 4c 24 12 c6 44 24 13 79 88 4c 24 14 c6 44 24 15 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 52 68 4b e1 22 00 50 ff 15 ?? ?? ?? ?? 85 c0 74 10 ff 15 ?? ?? ?? ?? 85 c0 75 06}  //weight: 1, accuracy: Low
        $x_1_4 = {00 5c 5c 2e 5c 53 53 44 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Veslorn_F_2147619807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Veslorn.gen!F"
        threat_id = "2147619807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Veslorn"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {79 6f 75 20 77 69 6c 6c 20 63 61 6e 27 74 20 72 65 67 69 73 74 20 70 72 6f 67 72 61 6d 00}  //weight: 5, accuracy: High
        $x_2_2 = {57 33 32 54 69 6d 65 5c 50 61 72 61 6d 65 74 65 72 73 00}  //weight: 2, accuracy: High
        $x_4_3 = {00 5c 46 59 44 44 4f 53 2e 64 6c 6c 00}  //weight: 4, accuracy: High
        $x_4_4 = {00 5c 78 63 6f 70 79 2e 65 78 65 00}  //weight: 4, accuracy: High
        $x_2_5 = {00 48 6f 6f 6b 69 6e 67 73 20 44 72 69 76 65 72 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Veslorn_G_2147641308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Veslorn.gen!G"
        threat_id = "2147641308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Veslorn"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "STOPATTACK" ascii //weight: 2
        $x_4_2 = "QrajUBysXpq]WbAcURqaWcL" ascii //weight: 4
        $x_3_3 = "/@kinvp>" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

