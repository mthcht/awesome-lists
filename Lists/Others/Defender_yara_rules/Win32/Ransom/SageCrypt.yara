rule Ransom_Win32_Sagecrypt_A_2147723930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sagecrypt.A!rsm"
        threat_id = "2147723930"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sagecrypt"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {61 63 79 22 20 3a 20 00 6c 61 74 22 20 3a 20 00 6c 6e 67 22 20 3a 20}  //weight: 10, accuracy: High
        $x_10_2 = "%s\\f%u.vbs" ascii //weight: 10
        $x_10_3 = {73 74 00 5c 5c 3f 5c 25 53 00 25 73 5c 66 25 75 2e 68 74 61}  //weight: 10, accuracy: High
        $x_10_4 = {7a 68 00 61 72 00 65 6e 00 64 65 00 65 73 00 66 61 00 66 72 00 69 74 00 6b 72 00 6e 6c 00 70 74 00 68 69 00 76 69 00 74 72 00 6d 73 00 6e 6f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sagecrypt_A_2147723930_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sagecrypt.A!rsm"
        threat_id = "2147723930"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sagecrypt"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 51 ff 83 c3 01 88 53 ff}  //weight: 2, accuracy: High
        $x_2_2 = {52 74 20 a1 ?? ?? ?? ?? 8b 98 ?? ?? 00 00 ff 90 ?? 00 00 00 c7 44 24 04 00 00 00 00 89 04 24 ff d3}  //weight: 2, accuracy: Low
        $x_1_3 = {c7 02 65 78 70 61 c7 42 04 6e 64 20 33 c7 42 08 32 2d 62 79 c7 42 0c 74 65 20 6b}  //weight: 1, accuracy: High
        $x_1_4 = {66 c7 40 1c 00 00 c7 00 01 23 45 67 c7 40 04 89 ab cd ef c7 40 08 fe dc ba 98 c7 40 0c 76 54 32 10 c7 40 10 f0 e1 d2 c3}  //weight: 1, accuracy: High
        $x_1_5 = {80 3c 33 2b 75 04 c6 04 33 2d 80 3c 33 2f 75 04 c6 04 33 5f}  //weight: 1, accuracy: High
        $x_2_6 = {43 00 3a 00 8b 7d 08 c7 45 ?? 5c 00 00 00 eb 11}  //weight: 2, accuracy: Low
        $x_2_7 = {66 83 3b 57 0f 85 ?? 00 00 00 66 83 7b 02 53 75 7b 66 83 7b 04 2d}  //weight: 2, accuracy: Low
        $x_3_8 = {0f 45 d9 8b 92 ?? ?? 00 00 89 5c 24 18 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 89 44 24 08 c7 44 24 04 50 41 f3 5c 89 3c 24 ff d2}  //weight: 3, accuracy: Low
        $x_2_9 = "[config---------" ascii //weight: 2
        $x_1_10 = {00 25 73 5c 25 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 25 73 5c 25 73 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_2_12 = {00 25 73 5c 66 25 75 2e 68 74 61 00}  //weight: 2, accuracy: High
        $x_2_13 = {00 25 73 5c 66 25 75 2e 76 62 73 00}  //weight: 2, accuracy: High
        $x_1_14 = {00 25 53 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_15 = {7a 68 00 61 72 00 65 6e 00 64 65 00 65 73}  //weight: 1, accuracy: High
        $x_1_16 = {68 69 00 76 69 00 74 72 00 6d 73 00 6e 6f}  //weight: 1, accuracy: High
        $x_1_17 = {00 61 63 79 22 20 3a 20 00}  //weight: 1, accuracy: High
        $x_1_18 = {00 6c 61 74 22 20 3a 20 00}  //weight: 1, accuracy: High
        $x_1_19 = {00 6c 6e 67 22 20 3a 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Sagecrypt_A_2147724279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sagecrypt.A!!Sagecrypt.gen!A"
        threat_id = "2147724279"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sagecrypt"
        severity = "Critical"
        info = "Sagecrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 51 ff 83 c3 01 88 53 ff}  //weight: 2, accuracy: High
        $x_2_2 = {52 74 20 a1 ?? ?? ?? ?? 8b 98 ?? ?? 00 00 ff 90 ?? 00 00 00 c7 44 24 04 00 00 00 00 89 04 24 ff d3}  //weight: 2, accuracy: Low
        $x_1_3 = {c7 02 65 78 70 61 c7 42 04 6e 64 20 33 c7 42 08 32 2d 62 79 c7 42 0c 74 65 20 6b}  //weight: 1, accuracy: High
        $x_1_4 = {66 c7 40 1c 00 00 c7 00 01 23 45 67 c7 40 04 89 ab cd ef c7 40 08 fe dc ba 98 c7 40 0c 76 54 32 10 c7 40 10 f0 e1 d2 c3}  //weight: 1, accuracy: High
        $x_1_5 = {80 3c 33 2b 75 04 c6 04 33 2d 80 3c 33 2f 75 04 c6 04 33 5f}  //weight: 1, accuracy: High
        $x_2_6 = {43 00 3a 00 8b 7d 08 c7 45 ?? 5c 00 00 00 eb 11}  //weight: 2, accuracy: Low
        $x_2_7 = {66 83 3b 57 0f 85 ?? 00 00 00 66 83 7b 02 53 75 7b 66 83 7b 04 2d}  //weight: 2, accuracy: Low
        $x_3_8 = {0f 45 d9 8b 92 ?? ?? 00 00 89 5c 24 18 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 89 44 24 08 c7 44 24 04 50 41 f3 5c 89 3c 24 ff d2}  //weight: 3, accuracy: Low
        $x_2_9 = "[config---------" ascii //weight: 2
        $x_1_10 = {00 25 73 5c 25 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 25 73 5c 25 73 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_2_12 = {00 25 73 5c 66 25 75 2e 68 74 61 00}  //weight: 2, accuracy: High
        $x_2_13 = {00 25 73 5c 66 25 75 2e 76 62 73 00}  //weight: 2, accuracy: High
        $x_1_14 = {00 25 53 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_15 = {7a 68 00 61 72 00 65 6e 00 64 65 00 65 73}  //weight: 1, accuracy: High
        $x_1_16 = {68 69 00 76 69 00 74 72 00 6d 73 00 6e 6f}  //weight: 1, accuracy: High
        $x_1_17 = {00 61 63 79 22 20 3a 20 00}  //weight: 1, accuracy: High
        $x_1_18 = {00 6c 61 74 22 20 3a 20 00}  //weight: 1, accuracy: High
        $x_1_19 = {00 6c 6e 67 22 20 3a 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Sagecrypt_YAA_2147911300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sagecrypt.YAA!MTB"
        threat_id = "2147911300"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sagecrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c 24 34 03 c1 8a 0c 13 8b 54 24 2c 32 c8 85 d2 74 0d 8b 54 24 ?? 88 0c 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

