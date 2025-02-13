rule VirTool_Win32_ObfuscatorGd_ObfuscatorGd_2147719224_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ObfuscatorGd!!ObfuscatorGd.gen!B"
        threat_id = "2147719224"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ObfuscatorGd"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 00 8b 45 f4 50 ff 95 ?? ?? ff ff 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff ff 75 05 e9 ?? ?? 00 00 6a 04 68 00 30 00 00 8b 8d ?? ?? ff ff 51 6a 00 ff 95}  //weight: 3, accuracy: Low
        $x_3_2 = {8b 55 f4 52 ff 95 ?? ?? ff ff 85 c0 75 05 e9 ?? ?? 00 00 8b 85 ?? ?? ff ff 89 85 ?? ?? ff ff 8b 8d ?? ?? ff ff 8b 51 3c}  //weight: 3, accuracy: Low
        $x_3_3 = {8d 44 0a 18 89 85 ?? ?? ff ff 6a 04 68 00 30 00 00 8b 8d ?? ?? ff ff 8b 51 ?? 52 6a 00 ff 95 ?? ?? ff ff 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff 00 75 05 e9}  //weight: 3, accuracy: Low
        $x_4_4 = {0f b6 02 3d b8 00 00 00 75 02 eb ?? 8b 4d fc 0f b6 11 81 fa e9 00 00 00 75}  //weight: 4, accuracy: Low
        $x_4_5 = {8d 44 0a 05 89 45 fc eb ?? 8b 4d fc 0f b6 11 81 fa ea 00 00 00 75 ?? 8b 45 fc 8b 48 01 89 4d fc eb}  //weight: 4, accuracy: Low
        $x_4_6 = {c2 04 00 8d 24 24 8d 24 24 8d 54 24 08 cd 2e c3}  //weight: 4, accuracy: High
        $x_3_7 = {68 02 01 00 00 ff 95 ?? ?? 00 00 68 00 80 00 00 6a 00 8b 55 ?? 52 ff 55 ?? 68 00 80 00 00 6a 00 8b 45 ?? 50 ff 55}  //weight: 3, accuracy: Low
        $x_3_8 = {68 00 80 00 00 6a 00 8b 4d ?? 51 ff 55 ?? 8b 45 ?? eb 02 33 c0 8b e5 5d c2 f0 00}  //weight: 3, accuracy: Low
        $x_3_9 = {b8 25 00 00 00 66 89 45 ?? b9 54 00 00 00 66 89 4d ?? ba 45 00 00 00 66 89 55 ?? b8 4d 00 00 00 66 89 45 ?? b9 50 00 00 00 66 89 4d ?? ba 25 00 00 00 66 89 55 ?? 33 c0 66 89 45 ?? c7 45 c8 00 00 00 00 6a 04 68 00 30 00 00 68 04 01 00 00}  //weight: 3, accuracy: Low
        $x_1_10 = {68 0b 6f d6 4a}  //weight: 1, accuracy: High
        $x_1_11 = {68 24 63 8d e9}  //weight: 1, accuracy: High
        $x_1_12 = {68 2c 0d 45 97}  //weight: 1, accuracy: High
        $x_1_13 = {68 5b ef 98 ee}  //weight: 1, accuracy: High
        $x_1_14 = {68 91 6c fd 88}  //weight: 1, accuracy: High
        $x_1_15 = {68 c8 cc e1 16}  //weight: 1, accuracy: High
        $x_1_16 = {68 cf 48 26 df}  //weight: 1, accuracy: High
        $x_1_17 = {68 f6 23 bb 49}  //weight: 1, accuracy: High
        $x_3_18 = {8a 0a 42 80 f9 ae 75 f8 84 c0 75 04 fe c0 eb f0}  //weight: 3, accuracy: High
        $x_2_19 = {8d 72 08 8b cb 8b 3e 89 4d f8 3b 7a 04 74 0d 41 8b c7 33 c1 3b 42 04 75 f6}  //weight: 2, accuracy: High
        $x_3_20 = {8a 44 0d f8 30 04 33 41 33 c0 83 f9 04 0f 44 c8 43 3b 1a 72 eb}  //weight: 3, accuracy: High
        $x_3_21 = {6a 10 6a 00 8d 45 ?? 50 e8 ?? ?? 00 00 6a 44 6a 00 8d 8d ?? ?? ff ff 51 e8 ?? ?? 00 00 6a 08 6a 00 8d 95 ?? ?? ff ff 52 e8}  //weight: 3, accuracy: Low
        $x_3_22 = {3d 4d 5a 00 00 74 07 33 c0 e9 ?? ?? 00 00 8b 4d ?? 8b 95 ?? ?? 00 00 03 51 3c 89 55 ?? 8b 45 ?? 81 38 50 45 00 00 75 0f 8b 4d ?? 0f b7 51 04 81 fa 4c 01 00 00}  //weight: 3, accuracy: Low
        $x_3_23 = {57 56 89 65 ?? 83 e4 f0 6a 33 e8 00 00 00 00 83 04 24 05 cb}  //weight: 3, accuracy: Low
        $x_3_24 = {5a 8b 45 08 0f 05 89 45 d4 03 65 ec e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb}  //weight: 3, accuracy: High
        $x_2_25 = {0f b7 4d f8 0f b7 55 f4 3b ca 74 07 b8 01 00 00 00 eb 07 e9 ?? ?? ff ff 33 c0 5e 8b e5 5d c2 08 00}  //weight: 2, accuracy: Low
        $x_2_26 = {0f be 4d fb 0f be 55 fa 3b ca 74 07 b8 01 00 00 00 eb 07 e9 ?? ?? ff ff 33 c0 5e 8b e5 5d c2 08 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

