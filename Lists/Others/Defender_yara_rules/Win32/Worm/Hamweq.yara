rule Worm_Win32_Hamweq_CM_121311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hamweq.CM"
        threat_id = "121311"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hamweq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "08B0E5C0-4FCB-11CF-AAX5-90401C608512" ascii //weight: 1
        $x_1_2 = "tassweq.com" ascii //weight: 1
        $x_1_3 = "ise.exe" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "gethostbyname" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Hamweq_A_122731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hamweq.A"
        threat_id = "122731"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hamweq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {7e 15 8b 06 8b 4c 24 ?? 03 c3 51 8a 14 29 30 10 45 ff d7 3b e8 7c eb 8b 06 03 c3 43 [0-2] f6}  //weight: 6, accuracy: Low
        $x_4_2 = {8a 04 10 32 04 31 8b 4d fc 8b 49 08 8b 55 f0 8b 0c d1 8b 55 f8 88 04 11 eb}  //weight: 4, accuracy: High
        $x_6_3 = {53 74 61 72 74 20 66 6c 6f 6f 64 69 6e 67 2e 00 46 6c 6f 6f 64 69 6e 67 20 64 6f 6e 65 2e 00 00 75 64 70 00 73 79 6e 00 66 73 74 6f 70 00}  //weight: 6, accuracy: High
        $x_3_4 = {59 6a 1a 99 59 f7 f9 80 c2 61 88 14 3e 46 3b 74 24 18 76}  //weight: 3, accuracy: High
        $x_2_5 = {59 99 6a 1a 59 f7 f9 83 c2 61 8b 45 0c 03 45 f8 88 10 eb}  //weight: 2, accuracy: High
        $x_2_6 = {3c 31 74 0d 3c 32 74 09 c7 45 fc 01 00 00 00 eb}  //weight: 2, accuracy: High
        $x_2_7 = {68 20 03 00 00 ff 50 68 66 89 45 e4 8b 06 68 78 56 34 12 ff 90 84 00 00 00 89 45 e8 8b 06 68 00 40 00 00}  //weight: 2, accuracy: High
        $x_2_8 = {68 20 03 00 00 8b 45 ?? 8b 00 ff 50 68 66 89 85 ?? ?? ?? ?? 68 78 56 34 12 8b 45 ?? 8b 00 ff 90 84 00 00 00}  //weight: 2, accuracy: Low
        $x_2_9 = {75 0b 6a 11 6a 02 6a 02 ff 50 5c eb 13 6a 01 53 53 68 ff 00 00 00 6a 03 6a 02 ff 90 80 00 00 00 83 f8 ff 89 45 08}  //weight: 2, accuracy: High
        $x_2_10 = {75 16 6a 11 6a 02 6a 02 8b 45 ?? 8b 00 ff 50 5c 89 85 ?? ?? ?? ?? eb 20 6a 01 6a 00 6a 00 68 ff 00 00 00 6a 03 6a 02 8b 45 ?? 8b 00 ff 90 80 00 00 00}  //weight: 2, accuracy: Low
        $x_2_11 = {eb 13 6a 01 53 53 68 ff 00 00 00 6a 03 6a 02 ff 90}  //weight: 2, accuracy: High
        $x_4_12 = {3c 42 0f 84 ?? ?? 00 00 3c 61 0f 84 ?? ?? 00 00 3c 62 0f 84 ?? ?? 00 00 8b 06 8d 4d ?? 51 ff 50 ?? 83 f8 02 0f 85}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Hamweq_B_127323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hamweq.gen!B"
        threat_id = "127323"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hamweq"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 15 8b 06 8b 4c 24 ?? 03 c3 51 8a 14 29 30 10 45 ff d7 3b e8 7c eb 8b 06 03 c3 43 [0-2] f6}  //weight: 1, accuracy: Low
        $x_1_2 = {59 6a 1a 99 59 f7 f9 80 c2 61 88 14 3e 46 3b 74 24 18 76}  //weight: 1, accuracy: High
        $x_1_3 = {80 f9 30 7c 0e 80 f9 39 7f 09 04 0d c0 e0 04 02 c1 eb 11 80 f9 41 7c 12 80 f9 46 7f 0d c0 e0 04 02 c1 2c 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Hamweq_AI_143382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hamweq.AI"
        threat_id = "143382"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hamweq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7e 15 8b 06 8b 4c 24 ?? 03 c3 51 8a 14 29 30 10 45 ff d7 3b e8 7c eb 8b 06 03 c3}  //weight: 3, accuracy: Low
        $x_1_2 = "WeDDings ServiCE" ascii //weight: 1
        $x_1_3 = {43 6f 64 65 64 20 03 34 42 79 20 03 38 56 69 72 55 73 2e 2e}  //weight: 1, accuracy: High
        $x_1_4 = "{67XOR2B0-3GMC-89VV-JIJ1-32KL5R3424444}" ascii //weight: 1
        $x_1_5 = {78 58 78 5f 78 5f 31 00 44 45 57 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {59 41 4d 30 53 34 48 33 6c 59 61 52 41 42 49 74 53 6d 59 57 65 44 44 69 4e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

