rule Ransom_Win32_Blackbyte_A_2147848368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Blackbyte.A!ibt"
        threat_id = "2147848368"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackbyte"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 56 65 48 8b 04 25 60 00 00 00 8b f1 80 78 02 00 0f 85 ?? ?? ?? 00 48 89 5c 24 10 33 db 48 89 7c 24 20 48 8b 78 18 48 83 c7 20 4c 8b 1f 4c 3b df 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {65 48 8b 04 25 60 00 00 00 45 33 db 8b e9 44 38 58 02 0f 85 ?? ?? 00 00 48 89 5c 24 ?? 48 89 7c 24 ?? 48 8b 78 18 48 83 c7 20 48 8b 1f 48 3b df 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_2_3 = {65 48 8b 04 25 60 00 00 00 48 8d 55 ?? 33 f6 89 75 ?? 48 8b 48 20 48 8b 49 78 e8 ?? ?? ?? ?? 83 7d ?? 03 48 8b d8 7d ?? 33 c9 ff 15 ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_4 = {ff c1 48 8d 40 01 80 38 00 75 f5 44 3b c1 7d 13 49 0f be 01 48 8d 14 52 48 03 d0 41 ff c0 49 ff c1 eb cd 48 3b d6 74 0c 4d 8b 1b 4c 3b df 0f 85 ?? ff ff ff}  //weight: 2, accuracy: Low
        $x_2_5 = {4d 8d 49 02 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f b7 c2 6b c8 ?? 41 0f b7 c0 41 ff c0 66 2b c1 66 83 c0 ?? 66 41 31 41 fe 41 83 f8 ?? 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

