rule Virus_Win32_Rayra_2147603105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Rayra"
        threat_id = "2147603105"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Rayra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {52 8b 48 3c 8b 4c 01 50 c6 45 f4 4f 51 50 89 0d ?? ?? 40 00 c6 45 f5 48 c6 45 f6 4d c6 45 f7 41 88 5d f8 e8 ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_2 = {b8 4d 5a 90 00 39 03 0f 85 19 03 00 00 83 7b 04 03 0f 85 0f 03 00 00 8b 4b 3c 8b 4c 19 fc 81 f9 01 02 00 00 0f 84 51 03 00 00 81 f9 01 02 00 55 0f 84 45 03 00 00 81 7b 38 43 53 4e 31 0f 84 38 03 00 00 81 ff f0 55 00 00 76 0d 39 84 3b fc af ff ff 0f 84 23 03 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {80 3f 50 0f 85 a7 02 00 00 80 7f 01 45 0f 85 9d 02 00 00 80 65 c8 00 8d 45 c4 50 56 53 c6 45 c4 74 c6 45 c5 65 c6 45 c6 78 c6 45 c7 74 e8 ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_1_4 = {01 50 0f 83 c1 23 89 8e d8 03 00 00 8b 48 23 89 8e dc 03 00 00 8b 4d e0 c7 40 23 00 00 00 e0 8b 45 ec 83 c1 07 89 8e e0 03 00 00 8b 48 07 89 8e e4 03 00 00 8b 48 0f 89 48 07 8d 86 b0 03 00 00 50 e8}  //weight: 1, accuracy: High
        $x_1_5 = {c6 45 e4 50 c6 45 e5 61 c6 45 e6 72 c6 45 e7 6d c6 45 e8 31 c6 45 e9 65 c6 45 ea 6e c6 45 eb 63 88 5d ec 68 02 00 00 80 c6 06 15 c6 46 01 ab c6 46 02 62 c6 46 03 94 c6 46 04 79 c6 46 05 9a c6 46 06 f9 c6 46 07 4a 88 5e 08 ff d7}  //weight: 1, accuracy: High
        $x_2_6 = {40 00 56 c6 05 ?? ?? 40 00 5c c6 05 ?? ?? 40 00 73 c6 05 ?? ?? 40 00 74 c6 05 ?? ?? 40 00 72 c6 05 ?? ?? 40 00 61 c6 05 ?? ?? 40 00 79 c6 05 ?? ?? 40 00 2e c6 05 ?? ?? 40 00 65 c6 05 ?? ?? 40 00 78 c6 05 ?? ?? 40 00 65}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

