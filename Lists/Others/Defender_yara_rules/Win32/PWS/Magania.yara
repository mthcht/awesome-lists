rule PWS_Win32_Magania_2147603208_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Magania"
        threat_id = "2147603208"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Magania"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {33 c9 89 0d ?? ?? ?? ?? 52 51 51 68 ?? ?? ?? ?? 51 51 e8 ?? ?? ?? ?? 58 6a 19 e8 ?? ?? ?? ?? 74 ?? 75}  //weight: 4, accuracy: Low
        $x_4_2 = {52 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8 ?? ?? 00 00 58 6a 03 01 01 01 19 32 1e e8 ?? ?? 00 00 [0-2] 74 ?? 75}  //weight: 4, accuracy: Low
        $x_4_3 = {50 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8 ?? ?? 00 00 83 c4 04 6a (0f|19) e8 ?? ?? 00 00 (74 ??|75 ??)}  //weight: 4, accuracy: Low
        $x_1_4 = {54 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8 ?? ?? ?? ?? 58 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0b c0 74}  //weight: 1, accuracy: Low
        $x_1_5 = {54 50 50 68 ?? ?? ?? ?? 50 50 e8 ?? ?? ?? ?? 58 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0b c0 74}  //weight: 1, accuracy: Low
        $x_1_6 = {50 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8 ?? ?? ?? ?? 83 c4 04 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0b c0 75 05 e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b c0 74 ?? 75}  //weight: 1, accuracy: Low
        $x_30_7 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 bf 4d 4a 00 00 b8 02 09 00 00 74 ?? 75}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*))) or
            ((1 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Magania_BQ_2147634533_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Magania.BQ"
        threat_id = "2147634533"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Magania"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3f 5d 3e a2 71 75 06 00 83 c7 04 83 e9 04}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7d 08 2e 62 6d 70 75 07 00 66 81 3f 4d 5a 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 08 32 e4 ac 32 02 2c 32 32 02 aa 42 fe c4 3a 65 0c}  //weight: 1, accuracy: High
        $x_2_4 = {c7 85 b0 fe ff ff 01 00 00 00 ff b5 d0 fe ff ff ff 93 ?? ?? ?? ?? 8d 8d d8 fe ff ff 51 ff b5 d4 fe ff ff ff 93 ?? ?? ?? ?? 0b c0 0f 85 5f fe ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

