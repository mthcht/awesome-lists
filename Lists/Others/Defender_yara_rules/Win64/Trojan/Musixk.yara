rule Trojan_Win64_Musixk_A_2147817253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Musixk.A"
        threat_id = "2147817253"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Musixk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c7 44 24 08 00 00 00 00 c7 44 24 08 ?? ?? ?? ?? 8b 44 24 08 35 ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 44 24 08 8b 44 24 08}  //weight: 3, accuracy: Low
        $x_3_2 = {48 8d 44 24 58 c7 44 24 58 41 00 45 00 c7 44 24 5c 53 00 00 00 48 8d 4d ef 48 89 44 24 50 45 33 c9 48 8b 54 24 50 45 33 c0 ff d7}  //weight: 3, accuracy: High
        $x_2_3 = {8d 77 01 4c 8d 3c c5 00 00 00 00 4c 8d 2d ?? ?? ?? ?? 66 0f 1f [0-7] 8b e6}  //weight: 2, accuracy: Low
        $x_2_4 = {0f b6 07 84 c0 74 ?? 3c 20 74 ?? 8b [0-10] 41 ff c0 48 ff c7}  //weight: 2, accuracy: Low
        $x_1_5 = {65 48 8b 04 25 60 00 00 00 83 b8 18 01 00 00 06 74 0e 83 b8 18 01 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Musixk_B_2147817254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Musixk.B"
        threat_id = "2147817254"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Musixk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c7 44 24 08 00 00 00 00 c7 44 24 08 ?? ?? ?? ?? 8b 44 24 08 35 ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 44 24 08 8b 44 24 08}  //weight: 3, accuracy: Low
        $x_2_2 = {48 c1 ea 17 48 2b f2 4c 8b f6 49 c1 ee 20 44 0f af f6 44 ?? ?? ?? ?? 45 33 c0 8d 53 04}  //weight: 2, accuracy: Low
        $x_1_3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 45 00 78 00 63 00 65 00 6c 00 [0-48] 45 00 72 00 72 00 6f 00 72 00 3a 00 20 00 43 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 73 00 74 00 61 00 72 00 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = {65 48 8b 04 25 60 00 00 00 83 b8 18 01 00 00 06 74 0e 83 b8 18 01 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

