rule Backdoor_Win32_Wkysol_A_2147617808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wkysol.A"
        threat_id = "2147617808"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wkysol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7d 21 8b 4d fc 33 d2 8a 54 0d 08 8b 45 fc 33 c9 8a 4c 05 4c 33 d1 8b 85 90 00 00 00 03 45 fc 88 10 eb ce}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 54 04 0c 8a 5c 04 50 32 d3 88 14 30 40 3b c1 7c ee}  //weight: 2, accuracy: High
        $x_5_3 = {54 43 50 09 50 49 44 3a 25 35 64 3b 09 50 4f 52 54 3a 25 35 64 09 50 41 54 48 3a 25 73}  //weight: 5, accuracy: High
        $x_5_4 = {31 39 39 39 30 38 31 37 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Wkysol_B_2147649835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wkysol.B"
        threat_id = "2147649835"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wkysol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 04 0c 8a 5c 04 50 32 d3 88 14 30 40 3b c1 7c ee}  //weight: 2, accuracy: High
        $x_2_2 = {83 f9 02 0f 82 ?? ?? 00 00 80 7d 00 63 0f 85 ?? ?? 00 00 80 7d 01 64 0f 85 ?? ?? 00 00 80 7d 02 20}  //weight: 2, accuracy: Low
        $x_2_3 = {8d 54 24 14 8d 44 24 28 52 68 f3 01 00 00 50 56 ff d7 85 c0 0f 84 ?? ?? 00 00 8b 44 24 14 85 c0 77 de}  //weight: 2, accuracy: Low
        $x_1_4 = {31 39 39 39 30 38 31 37 00}  //weight: 1, accuracy: High
        $x_1_5 = "kys_allow_get.asp?name=getkys.kys" ascii //weight: 1
        $x_1_6 = "kys_allow_put.asp?type=" ascii //weight: 1
        $x_1_7 = "PID:%5d    PATH:%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Wkysol_D_2147652108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wkysol.D"
        threat_id = "2147652108"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wkysol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 2f 6b 79 73 5f 61 6c 6c 6f 77 5f 67 65 74 2e 61 73 70 3f 6e 61 6d 65 3d 67 65 74 6b 79 73 2e 6b 79 73 00 25 73 0a 00 6f 75 74 6c 6f 6f 6b 00 69 65 78 70 6c 6f 72 65 00 00 00 00 66 69 72 65 66 6f 78 2e 65 78 65 00 6f 75 74 6c 6f 6f 6b 2e 65 78 65 00 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {70 2f 6b 79 73 5f 61 6c 6c 6f 77 5f 67 65 74 2e 61 73 70 3f 6e 61 6d 65 3d 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 25 73 00 00 70 64 74 70 72 65 74 74 79 2e 74 6d 70 00 00 00 67 64 74 70 72 65 74 74 79 2e 74 6d 70 00 00 00 70 74 70 72 65 74 74 79 2e 74 6d 70 00 00 00 00 67 74 70 72 65 74 74 79 2e 74 6d 70 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Wkysol_E_2147652176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wkysol.E"
        threat_id = "2147652176"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wkysol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bb 01 eb 09 66 c7 85 ?? ?? ?? ?? 50 00 6a 00 6a 00 6a 03 68 07 00 66 c7 85}  //weight: 2, accuracy: Low
        $x_2_2 = {80 c9 80 89 8d ?? ?? ?? ?? 6a 04 8d 95 00 52 6a 1f 8b 85 ?? ?? ?? ?? 50 ff 15}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 04 50 80 c9 80 6a 1f 56 89 4c 24 ?? ff d3}  //weight: 2, accuracy: Low
        $x_2_4 = {10 0e 00 00 ff 15 ?? ?? ?? ?? 99 b9 08 07 00 00 f7 f9 03 d1 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? ff d3}  //weight: 2, accuracy: Low
        $x_2_5 = "kys_allow_get.asp?name=getkys" ascii //weight: 2
        $x_2_6 = {31 39 39 39 30 38 31 37 00}  //weight: 2, accuracy: High
        $x_1_7 = "put.asp?type=" ascii //weight: 1
        $x_1_8 = "PID:%5d    PATH:%s" ascii //weight: 1
        $x_1_9 = "chksrv.tmp" ascii //weight: 1
        $x_2_10 = "-removekys" ascii //weight: 2
        $x_1_11 = "AC_XSI_UtilGetCardStatus" ascii //weight: 1
        $x_2_12 = {6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 68 74 74 70 5f 70 6f 72 74 00 4e 55 4c 4c 00 00 00 00 70 72 65 66 73 2e 6a 73}  //weight: 2, accuracy: High
        $x_2_13 = "get.asp?name=get.js" ascii //weight: 2
        $x_2_14 = {73 63 64 6c 6c 00 00 00 73 63 65 78 65 00 00 00 75 72 6c 00 73 6c 65 65 70 74 69 6d 65 00 00 00 73 72 76 5f 69 6e 66 6f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Wkysol_F_2147652183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wkysol.F"
        threat_id = "2147652183"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wkysol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 7c 24 1c 53 75 ce 80 7c 24 1d 55 75 c7 8b 44 24 1e 50 e8}  //weight: 2, accuracy: High
        $x_2_2 = {66 c7 44 24 10 02 00 e8 ?? ?? ?? ?? 68 ?? 04 00 00 89 44 24 14 e8 ?? ?? ?? ?? 66 89 44 24 0e 8d 44 24 0c 6a 10 50 55 33 f6 e8}  //weight: 2, accuracy: Low
        $x_1_3 = "?a1=%s&a2=%s&a3=%d&a5=%s&a4=%s&a6=%" ascii //weight: 1
        $x_1_4 = "JAGEXLAUNCHER.EXE" ascii //weight: 1
        $x_1_5 = "GuardCore.dll" ascii //weight: 1
        $x_1_6 = "WTF\\Config.wtf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Wkysol_I_2147657594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wkysol.I"
        threat_id = "2147657594"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wkysol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/get.asp?nm=index.dat" ascii //weight: 1
        $x_1_2 = {8b 87 a0 01 00 00 83 e8 06 74 ?? 83 e8 03 74 ?? 83 e8 06 74 ?? 83 e8 08 74 ?? 48 74 ?? 83 e8 04 8d 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Wkysol_J_2147659619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wkysol.J"
        threat_id = "2147659619"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wkysol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "/put.asp?nm=" ascii //weight: 1
        $x_1_3 = "/get.asp?nm=index.dat" ascii //weight: 1
        $x_1_4 = {52 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 20 02 00 00 6a 20 6a 02 8d 45 dc 50 ff 15}  //weight: 1, accuracy: High
        $x_1_5 = {80 c9 80 89 8d ?? ?? ?? ?? 6a 04 8d 95 00 52 6a 1f 8b 85 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = {8d 55 a8 52 53 53 53 53 53 53 68 20 02 00 00 6a 20 6a 02 8d 45 dc 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

