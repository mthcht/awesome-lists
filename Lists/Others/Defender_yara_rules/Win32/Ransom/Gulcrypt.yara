rule Ransom_Win32_Gulcrypt_A_2147688245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gulcrypt.A"
        threat_id = "2147688245"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gulcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*.ChipDale" ascii //weight: 1
        $x_1_2 = "PING -n 5 -w 1000 127.0.0.1 > nul" ascii //weight: 1
        $x_1_3 = "del systemTrayW.exe" ascii //weight: 1
        $x_1_4 = {00 63 68 69 70 5f 61 6e 64 5f 64 61 6c 65 2e 76 7a 68 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gulcrypt_A_2147688245_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gulcrypt.A"
        threat_id = "2147688245"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gulcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a ed e0 e6 ec e8 f2 e5 20 ea ed ee ef ea f3 20 43 72 65 61 74 65 20 72 61 6e 64 6f 6d 20 61 64 64 72 65 73 73 2e 20 c2 f1 e5 2c 20 e2 fb 20 ec}  //weight: 1, accuracy: High
        $x_1_2 = {ea ed ee ef ea f3 20 53 65 6e 64 20 4d 65 73 73 61 67 65 0d 0a 28 ef ee f1 eb e0 f2 fc 20 f1 ee}  //weight: 1, accuracy: High
        $x_5_3 = {21 21 d4 e0 e9 eb fb 20 e7 e0 f8 e8 f4 f0 ee e2 e0 ed fb [0-5] 2e 74 78 74 00}  //weight: 5, accuracy: Low
        $x_5_4 = {b9 19 00 00 00 bb 01 00 00 00 d3 e3 23 d8 74 2d 80 c1 41 88 0d ?? ?? 40 00 80 e9 41 c7 05 ?? ?? 40 00 3a 5c 2a 2e c6 05 ?? ?? 40 00 2a c6 05 ?? ?? 40 00 00 50 51 e8 ?? ?? ff ff 59 58 49 7d c5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Gulcrypt_B_2147691452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gulcrypt.B"
        threat_id = "2147691452"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gulcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@Files_your_iD" ascii //weight: 1
        $x_1_2 = {2f 61 73 6d 2f 74 65 73 74 2e 70 68 70 00 68 65 6c 6c 6f 3d}  //weight: 1, accuracy: High
        $x_1_3 = "bukashka" ascii //weight: 1
        $x_1_4 = "plogaero" ascii //weight: 1
        $x_1_5 = {21 c2 ee f1 f1 f2 e0 ed ee e2 e8 f2 fc 20}  //weight: 1, accuracy: High
        $x_1_6 = {2f 74 61 73 6b 2f 72 65 73 2e 70 68 70 00 68 65 6c 6c 6f 3d}  //weight: 1, accuracy: High
        $x_2_7 = {b9 19 00 00 00 bb 01 00 00 00 d3 e3 23 d8 74 2d 80 c1 41 88 0d 00 30 40 00 80 e9 41 c7 05 01 30 40 00 3a 5c 2a 2e c6 05 05 30 40 00 2a c6 05 06 30 40 00 00 50 51 e8 7b f7 ff ff}  //weight: 2, accuracy: High
        $x_1_8 = {c7 80 00 30 40 00 5c 2a 2e 2a c6 80 04 30 40 00 00 e8 54 ff ff ff 58 c7 80 ff 2f 40 00 5c 2a 2e 2a c6 80 03 30 40 00 00 e9 67 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Gulcrypt_B_2147691452_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gulcrypt.B"
        threat_id = "2147691452"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gulcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 01 10 10 00 7d}  //weight: 1, accuracy: High
        $x_1_2 = {8b c8 c7 45 ?? 11 01 10 00 89 55}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 f8 50 ff 75 ?? ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {89 45 fa 8b 85 bc fe ff ff 83 e0 10 0f 84 ?? 00 00 00 8d 85 e8 fe ff ff 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_2_5 = {5c 2a 2e 2a c6 80 ?? ?? ?? ?? 00 e8 ?? ff ff ff 58 c7 80 ?? ?? ?? ?? 5c 2a 2e 2a c6 80 ?? ?? ?? ?? 00 e9 ?? ?? 00 00 8d 85 ?? fe ff ff 50 e8 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_2_6 = {bb 01 00 00 00 d3 e3 23 d8 74 ?? 80 c1 41 88 0d ?? ?? ?? ?? 80 e9 41 c7 05 ?? ?? ?? ?? 3a 5c 2a 2e [0-1] c6 05 ?? ?? ?? ?? 2a c6 05 ?? ?? ?? ?? 00 50 51 e8 ?? ?? ?? ?? 59 58 49 7d 05 00 b9 ?? 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

