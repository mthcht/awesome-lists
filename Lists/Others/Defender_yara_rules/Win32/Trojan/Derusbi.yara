rule Trojan_Win32_Derusbi_G_2147691848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Derusbi.G!dha"
        threat_id = "2147691848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "93144EB0-8E3E-4591-B307-8EEBFE7DB28F" wide //weight: 100
        $x_100_2 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 [0-16] 2d 25 73 2d 25 30 33 64 [0-16] 2d 25 30 33 64}  //weight: 100, accuracy: Low
        $x_100_3 = "ZwLoadDriver" ascii //weight: 100
        $x_100_4 = "ZhuDongFangYu.exe" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Derusbi_H_2147691849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Derusbi.H!dha"
        threat_id = "2147691849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "%s\\rundll32.exe %s,zxFunction001 %s" ascii //weight: 10
        $x_3_2 = "ShareShell IP Port -nc" ascii //weight: 3
        $x_3_3 = "Password: %s" ascii //weight: 3
        $x_5_4 = {46 75 63 6b (4a 50|4b 52) 78 78 78}  //weight: 5, accuracy: Low
        $x_5_5 = "Global\\fcKRxxx" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Derusbi_B_2147693985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Derusbi.B!dha"
        threat_id = "2147693985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 75 6c ff 55 54 e9 ca 01 00 00 83 f9 12 75 0c 8b 46 04 81 0e 00 00 04 00 89 46 04 83 f9 11 75 0c 8b 46 04}  //weight: 1, accuracy: High
        $x_1_2 = {ff 75 6c ff 55 5c 85 c0 75 09 8b 46 04 83 0e 20 89 46 04 8d 45 64 50 8d 85}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 60 63 c6 45 61 75 c6 45 62 74 c6 45 63 65 c6 45 64 45 c6 45 65 78 c6 45 66 57 88 5d 67 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {33 db 3b c3 75 04 33 c0 eb 1d 8d 4c 24 18 51 33 f6 ff d0 0f b7 44 24 18 83 f8 06 74 05 83 f8 09 75 03 33 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Derusbi_F_2147693986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Derusbi.F!dha"
        threat_id = "2147693986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f9 1c 7c e2 33 c9 8a c1 b2 07 f6 ea 30 44 0d d8 41 83 f9 1c 7c f0}  //weight: 1, accuracy: High
        $x_1_2 = {30 4c 05 84 40 83 f8 2e 72 f6 33 c0 30 4c 05 b4 40 83 f8 13 72 f6}  //weight: 1, accuracy: High
        $x_1_3 = "\\dw15.exe" ascii //weight: 1
        $x_1_4 = "%%TEMP%%\\%s_p.ax" ascii //weight: 1
        $x_1_5 = {47 45 54 20 68 74 74 70 3a 2f 2f 00 25 5b 5e 3a 5d 3a 25 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Derusbi_C_2147693987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Derusbi.C!dha"
        threat_id = "2147693987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ace123dx" ascii //weight: 1
        $x_1_2 = "LoadConfigFromReg failded" ascii //weight: 1
        $x_1_3 = "LoadConfigFromBuildin success" ascii //weight: 1
        $x_1_4 = "/photoe/photo.asp HTTP" ascii //weight: 1
        $x_1_5 = "~DFTMP$$$$$.1" ascii //weight: 1
        $x_1_6 = "Dom4!nUserP4ss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Derusbi_D_2147693988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Derusbi.D!dha"
        threat_id = "2147693988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_SvcCtrlFnct@4" ascii //weight: 1
        $x_1_2 = {6a 40 68 00 10 00 00 68 00 50 00 00 6a 00 ff 15 ?? ?? ?? ?? 89 45 fc 33 c0 8a 88 ?? ?? ?? ?? 80 f1 ?? 88 8c 05 bc ec ff ff 40 3d ?? 13 00 00 7c e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Derusbi_E_2147693989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Derusbi.E!dha"
        threat_id = "2147693989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 f8 28 75 09 c7 45 ?? 5b 44 5d 00 eb 24 83 f8 2e 75 07 be ?? ?? ?? ?? eb 0a 83 f8 2d 75 13 be}  //weight: 2, accuracy: Low
        $x_1_2 = "\\SystemRoot\\temp\\ziptmp$" wide //weight: 1
        $x_1_3 = "\\Driver\\Kbdclass" wide //weight: 1
        $x_1_4 = {5b 49 4e 53 5d 00 5b 44 45 4c 5d 00 5b 45 4e 44 5d 00 5b 48 4f 4d 45 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Derusbi_J_2147712656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Derusbi.J!bit"
        threat_id = "2147712656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 65 63 68 6f 20 6f 66 66 0d 0a 70 69 6e 67 20 31 32 37 2e 31 20 3e 20 6e 75 6c 0d 0a 6e 65 74 20 73 74 6f 70 20 25 25 31 0d 0a 70 69 6e 67 20 31 32 37 2e 31 20 3e 20 6e 75 6c 0d 0a 6e 65 74 20 73 74 61 72 74 20 25 25 31 0d 0a 70 69 6e 67 20 31 32 37 2e 31 20 3e 20 6e 75 6c 0d 0a 64 65 6c 20 25 25 30 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = "varus_service_x86.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

