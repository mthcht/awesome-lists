rule Worm_Win32_Morto_A_2147648848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Morto.gen!A"
        threat_id = "2147648848"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Morto"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 0c 46 46 47 47 84 ?? 75 e2 19 00 [0-18] 75 1a 84 ?? 74 12 8a}  //weight: 2, accuracy: Low
        $x_2_2 = {64 a1 30 00 00 00 89 45 fc 8b 45 fc 8b 40 0c 8b 78 10 8b 70 0c 3b f7 74 1f}  //weight: 2, accuracy: High
        $x_1_3 = {eb 24 3c 41 7c 0f 3c 5a 7f 0b 0f be c0 8a}  //weight: 1, accuracy: High
        $x_1_4 = {53 59 53 54 c7 45 ?? 45 4d 5c 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Morto_B_2147649411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Morto.B"
        threat_id = "2147649411"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Morto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 0c ff 76 30 ff 75 08 ff 15 ?? ?? ?? ?? 83 c4 0c 85 c0 74 04 8b 36 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 0c 89 85 ?? ?? ?? ?? 68 00 02 00 00 8d 85 f0 fd ff ff 50 ff 75 08 ff 95}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 08 50 c7 45 b0 4b 00 65 00 c7 45 b4 72 00 6e 00 c7 45 b8 65 00 6c 00 c7 45 bc 33 00 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Morto_C_2147649883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Morto.C"
        threat_id = "2147649883"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Morto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 32 74 17 8b 85 ?? ?? ff ff 0f be 00 8b 8d ?? ?? ff ff 03 c8}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 3f 8b ff 75 02 00 47 47}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 45 f8 8a 4d 10 03 c6 28 08 46 3b 75 0c 72}  //weight: 2, accuracy: High
        $x_1_4 = {53 59 53 54 c7 45 ?? 45 4d 5c 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Morto_D_2147650875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Morto.D"
        threat_id = "2147650875"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Morto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 0c 8b 46 30 50 ff 75 08 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 fc 8d 7e 04 50 6a 40 57 ff 75 08 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 72 76 69 63 65 48 61 6e 64 6c 65 72 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_4 = {83 f8 32 74 17 8b 85 ?? ?? ff ff 0f be 00 8b 8d ?? ?? ff ff 03 c8}  //weight: 1, accuracy: Low
        $x_1_5 = {66 81 3f 8b ff 75 02 00 47 47}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 1c 03 00 ff 15 ?? ?? ?? ?? 59 89 85 ?? ?? ff ff 83 a5 ?? ?? ff ff 00 c7 85 ?? ?? ff ff 00 1c 03 00}  //weight: 1, accuracy: Low
        $x_1_7 = {b8 72 00 6e 00 89 45 ?? b8 65 00 6c 00 89 45 ?? b8 33 00 32 00 89 45 ?? b8 00 00 00 00 89 45 ?? b8 4b 00 65 00 89 45 ?? 8d 45 ?? 6a 08 50 e8}  //weight: 1, accuracy: Low
        $x_1_8 = {ff 75 0c 8b 46 30 50 ff 75 08 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 74 0d 8b 36 3b f7 75 d8}  //weight: 1, accuracy: Low
        $x_3_9 = {c7 45 f4 4d 61 69 6e c7 45 f8 54 68 72 65 ff 30 c7 45 fc 61 64 00 00 ff 15}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Morto_E_2147651244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Morto.E"
        threat_id = "2147651244"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Morto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 08 8a 8c 0d 80 fd ff ff eb 88 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 0c 8b 45 08 80 38 00 74 05 80 3e 00 75 0a 83 7d 10 00}  //weight: 1, accuracy: High
        $x_1_3 = {ff 45 fc 83 45 f8 04 8b 45 fc 83 45 f4 02 3b 46 18 0f 82 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

