rule TrojanSpy_Win32_Rebhip_C_2147691419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rebhip.C"
        threat_id = "2147691419"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "####@#### ####@####" ascii //weight: 6
        $x_1_2 = "CG-CG-CG-CG" wide //weight: 1
        $x_1_3 = "XX-XX-XX-XX" wide //weight: 1
        $x_1_4 = {06 00 53 00 50 00 59 00 4e 00 45 00 54 00}  //weight: 1, accuracy: High
        $x_1_5 = "|Spy-Net [RAT]|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Rebhip_A_2147691441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rebhip.A!upx"
        threat_id = "2147691441"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        info = "upx: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "x_X_BLOCKMOUSE" ascii //weight: 3
        $x_3_2 = {2e 61 62 63 00}  //weight: 3, accuracy: High
        $x_1_3 = "CG-CG-CG-CG" wide //weight: 1
        $x_1_4 = "XX-XX-XX-XX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Rebhip_D_2147691468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rebhip.D!dll"
        threat_id = "2147691468"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "xX_PROXY_SERVER_Xx" ascii //weight: 2
        $x_1_2 = {66 75 6e 63 6f 65 73 2e 64 6c 6c 00 45 6e 76 69 61 72 53 74 72 65 61 6d 00 47 65 74 43 68 72 6f 6d 65 50 61 73 73 00 47 65 74 43 6f 6e 74 61 63 74 4c 69 73 74 00 47 65 74 43 75 72 72 65 6e 74 4d 53 4e 53 65 74 74 69 6e 67 73 00 47 65 74 4d 53 4e 53 74 61 74 75 73 00 4d 6f 7a 69 6c 6c 61 33 5f 35 50 61 73 73 77 6f 72 64 00 53 65 74 4d 53 4e 53 74 61 74 75 73 00 53 74 61 72 74 48 74 74 70 50 72 6f 78 79}  //weight: 1, accuracy: High
        $x_1_3 = {66 75 6e 63 6f 65 73 2e 64 6c 6c 00 45 6e 76 69 61 72 53 74 72 65 61 6d 00 53 74 61 72 74 48 74 74 70 50 72 6f 78 79 00 53 74 61 72 74 53 6f 63 6b 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Rebhip_C_2147691589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rebhip.C!A"
        threat_id = "2147691589"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_7_1 = "####@#### ####@####" ascii //weight: 7
        $x_1_2 = {55 6e 69 74 44 69 76 65 72 73 6f 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {55 6e 69 74 43 6f 6d 61 6e 64 6f 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 55 6e 69 74 56 61 72 69 61 76 65 69 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {55 6e 69 74 53 61 6e 64 42 6f 78 00}  //weight: 1, accuracy: High
        $x_1_6 = {55 6e 69 74 49 6e 6a 65 63 74 4c 69 62 72 61 72 79 00}  //weight: 1, accuracy: High
        $x_1_7 = {5f 50 45 52 53 49 53 54 00}  //weight: 1, accuracy: High
        $x_1_8 = {5f 53 41 49 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_7_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Rebhip_F_2147705774_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rebhip.F"
        threat_id = "2147705774"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {23 23 23 23 40 23 23 23 23 00}  //weight: 1, accuracy: High
        $x_1_2 = {5f 50 45 52 53 49 53 54 00}  //weight: 1, accuracy: High
        $x_1_3 = {e3 fe f3 f3 e8}  //weight: 1, accuracy: High
        $x_1_4 = {f4 f7 f9 e5 e3 ff f0 fd ef ef f9 ef e3 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Rebhip_G_2147714375_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rebhip.G"
        threat_id = "2147714375"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "UnitComandos" ascii //weight: 1
        $x_1_2 = {5c 53 70 79 2d 4e 65 74 20 5b 52 41 54 5d 20 [0-8] 5c 53 65 72 76 65 72 5c 50 6c 75 67 69 6e 44 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {66 69 6c 65 6d 61 6e 61 67 65 72 7c 74 68 75 6d 62 70 72 6f 67 72 65 73 73 7c 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 61 6d 73 70 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {74 68 75 6d 62 6e 61 69 6c 7c 58 58 58 7c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Rebhip_H_2147716733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rebhip.H"
        threat_id = "2147716733"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 d6 6b fa 47 8b 53 30 8d 54 ba 20}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 c6 6b c0 47 8b 53 30 8d 94 82 20 01 00 00 8b 43 30 8d 44 b8 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Rebhip_H_2147716733_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rebhip.H"
        threat_id = "2147716733"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 50 59 5f 4e 45 54 5f 52 41 54 4d 55 54 45 58 00}  //weight: 1, accuracy: High
        $x_1_2 = {58 58 2d 2d 58 58 2d 2d 58 58 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_2_3 = {6e 6a 6b 76 65 6e 6b 6e 76 6a 65 62 63 64 64 6c 61 6b 6e 76 66 64 76 6a 6b 66 64 73 6b 76 00}  //weight: 2, accuracy: High
        $x_2_4 = {6e 6a 67 6e 6a 76 65 6a 76 6f 72 65 6e 77 74 72 6e 69 6f 6e 72 69 6f 6e 76 69 72 6f 6e 76 72 6e 76 63 67 31 30 37 00}  //weight: 2, accuracy: High
        $x_2_5 = {6e 6a 67 6e 6a 76 65 6a 76 6f 72 65 6e 77 74 72 6e 69 6f 6e 72 69 6f 6e 76 69 72 6f 6e 76 72 6e 76 63 67 31 31 37 00}  //weight: 2, accuracy: High
        $x_1_6 = "####@#### ####" ascii //weight: 1
        $x_1_7 = "XX-XX-XX-XX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Rebhip_I_2147718250_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rebhip.I"
        threat_id = "2147718250"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 6e 69 74 46 75 6e 63 6f 65 73 44 69 76 65 72 73 61 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 6e 69 74 44 69 76 65 72 73 6f 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {55 6e 69 74 49 6e 73 65 72 74 50 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 6e 69 74 52 65 76 50 72 6f 78 79 50 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 70 79 4e 65 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

