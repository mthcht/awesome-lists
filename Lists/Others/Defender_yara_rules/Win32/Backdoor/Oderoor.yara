rule Backdoor_Win32_Oderoor_A_2147598033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Oderoor.gen!A"
        threat_id = "2147598033"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Oderoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {63 72 63 00 5c 64 72 69 76 65 72 73 5c}  //weight: 2, accuracy: High
        $x_2_2 = {70 6f 72 74 32 35 00 00 77 69 6e 64 6f 77 73 76}  //weight: 2, accuracy: High
        $x_2_3 = {75 70 74 69 6d 65 00 00 73 75 70 65 72 6e 6f 64}  //weight: 2, accuracy: High
        $x_2_4 = {6e 73 65 72 76 2e 63 6f 6d 00 79 69 2e 6f 72 67}  //weight: 2, accuracy: High
        $x_2_5 = {3c 2f 6f 70 74 69 6f 6e 00 00 00 00 52 65 66 65}  //weight: 2, accuracy: High
        $x_1_6 = "tion: form-data;" ascii //weight: 1
        $x_1_7 = {41 55 54 48 20 4c 4f 47 49 4e 0d 0a 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {4d 41 49 4c 20 46 52 4f 4d 3a 20 3c 25 73 3e 0d}  //weight: 1, accuracy: High
        $x_1_9 = "csv|txt|wab" ascii //weight: 1
        $x_1_10 = {68 61 72 76 65 73 74 00 65 6d 61 69 6c 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Oderoor_D_2147605657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Oderoor.gen!D"
        threat_id = "2147605657"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Oderoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {68 56 52 41 48 50 e8}  //weight: 4, accuracy: High
        $x_5_2 = {8d 7d f8 a5 66 a5 a4 33 db 8a c3 04 61 8d 4c 1d ?? 88 41 ?? 8b c3 99 6a 06 5e f7 fe 83 fb 0a 8a 44 15 f8 88 01 7d 07 8a c3 04 30 88 41 ?? 43 83 fb 1a 7c}  //weight: 5, accuracy: Low
        $x_5_3 = {b9 ea d8 00 00 f7 f1 6a 06 6a 01 6a 02 81 c2 10 27 00 00 0f b7 f2}  //weight: 5, accuracy: High
        $x_3_4 = {8a 00 3c 2a 74 ?? 3c 2b 74 ?? 3c 3f 74}  //weight: 3, accuracy: Low
        $x_2_5 = {8b 87 1c 04 00 00 0f be 00 85 c0 74 ?? 83 f8 7c 74 ?? 83 f8 29 74}  //weight: 2, accuracy: Low
        $x_4_6 = {6a 01 6a 03 6a 02 ff 15 [0-64] 48 48 48 48 ff 15}  //weight: 4, accuracy: Low
        $x_4_7 = {3d 6f 7a 6c 6d 74 04 33 c0}  //weight: 4, accuracy: High
        $x_3_8 = {8b 07 80 38 23 75 ?? 81 78 01 65 6e 63 23 75}  //weight: 3, accuracy: Low
        $x_6_9 = {b8 00 00 00 00 0f a2 01 06 01 56 04 b8 01 00 00 00 0f a2 31 06 31 56 04 b8 03 00 00 00 0f a2 31 16 31 4e 04 68 04 01 00 00 8d 85 ?? ?? ?? ff 50 ff 15 ?? ?? ?? ?? 8a 8d ?? ?? ?? ff 0f b6 c1 2c 61 b2 19 3a d0}  //weight: 6, accuracy: Low
        $x_4_10 = {6d 72 74 73 74 75 62 2e 65 78 65 00 6d 72 74 2e 65 78 65 00}  //weight: 4, accuracy: High
        $x_3_11 = {67 72 6f 00 6d 6f 63 00 74 65 6e}  //weight: 3, accuracy: High
        $x_3_12 = {74 65 6e 00 6d 6f 63 00 67 72 6f 00 6f 63 00}  //weight: 3, accuracy: High
        $x_2_13 = {6e 6d 74 73 00 00 00 00 61 6f 65 69 79 75 00}  //weight: 2, accuracy: High
        $x_2_14 = {61 6f 65 69 79 75 00 00 6e 6d 74 73 00}  //weight: 2, accuracy: High
        $x_1_15 = {25 64 2c 25 64 2c 25 73 2c 25 73 2c 25 73 0a 00 25 64 2c 25 64 2c 25 73 0a 00}  //weight: 1, accuracy: High
        $x_2_16 = "CcspxXuid%" ascii //weight: 2
        $x_2_17 = "cCdipsuxX%" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_6_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Oderoor_H_2147624995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Oderoor.gen!H"
        threat_id = "2147624995"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Oderoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 01 00 00 00 f0 0f c1 01 40 83 3d ?? ?? ?? 00 00 75 08 8d 85 00 ff ff ff eb 06}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 85 00 ff ff ff 0a c0 74 09 83 3d ?? ?? ?? 00 00 76 e6}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 ac 50 8d 45 bc 50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Oderoor_M_2147682601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Oderoor.M"
        threat_id = "2147682601"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Oderoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 63 73 70 78 58 75 69 64 25 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 06 80 38 23 75 1a 81 78 01 65 6e 63 23 75 11 6a 05 ff 75 08 8b ce e8}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 50 02 0f b6 48 03 03 ca 0f b6 50 01 0f b6 00 03 ca 03 c8 81 f9 02 02 00 00 75 5a 57 56 8d 4d f8 e8}  //weight: 1, accuracy: High
        $x_1_4 = {8b d8 85 db 75 04 32 c0 eb 6a 56 8d 85 d8 fe ff ff 50 53 c7 85 d8 fe ff ff 28 01 00 00 33 f6 e8}  //weight: 1, accuracy: High
        $x_1_5 = {33 c9 84 c0 0f 95 c1 89 5d fc 81 c1 01 00 00 80 89 4d f4 0f 31 03 c2 89 45 fc c7 45 f8 02 00 00 00 8d 45 a4 50 8d 45 c4 50 8b cf e8}  //weight: 1, accuracy: High
        $x_1_6 = {81 ec 24 04 00 00 83 65 fc 00 53 56 57 8b d8 8d 79 fc 8a 03 43 3c 25 75 71 33 f6 88 45 dc 46 8a 03 88 44 35 dc 0f be 44 35 dc 43 46 50 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

