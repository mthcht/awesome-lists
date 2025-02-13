rule Rogue_Win32_Trapwot_206303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Trapwot"
        threat_id = "206303"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Trapwot"
        severity = "18"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "{A14EF3FF-EB89-4FF8-B870-F058C1ABFC45}" ascii //weight: 2
        $x_2_2 = "//e:vbscript //B //NOLOGO \"AV Name\" \"{8E5CADC3-2C41-4886-B211-9C1D59EDD30F}\"" ascii //weight: 2
        $x_1_3 = "Defender PRO 2015 installation Setup" ascii //weight: 1
        $x_1_4 = "DefendrvPro.exe" ascii //weight: 1
        $x_1_5 = "Malware Defender 2015 installation Setup" ascii //weight: 1
        $x_1_6 = "MDefender.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Trapwot_206303_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Trapwot"
        threat_id = "206303"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Trapwot"
        severity = "18"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 67 67 63 3a 2f 2f [0-16] 2f 76 7a 74 2f 63 63 70 2e 72 6b 72}  //weight: 10, accuracy: Low
        $x_1_2 = {6a 76 61 76 61 72 67 00}  //weight: 1, accuracy: High
        $x_1_3 = "Vagrearg" ascii //weight: 1
        $x_1_4 = "PerngrCebprffN" ascii //weight: 1
        $x_1_5 = "TrgGrzcCnguN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Trapwot_206303_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Trapwot"
        threat_id = "206303"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Trapwot"
        severity = "18"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 c7 14 80 3f 4d 75 ?? 80 7f 01 5a 75 ?? 3b 5d 08 73}  //weight: 4, accuracy: Low
        $x_1_2 = {b8 4f ec c4 4e f7 e1 c1 ea 03 6b d2 1a 2b ca 0f be 55 ff 3b ca 75}  //weight: 1, accuracy: High
        $x_1_3 = "/get_two.php?" ascii //weight: 1
        $x_1_4 = {52 75 6e 49 6e 76 61 6c 69 64 53 69 67 6e 61 74 75 72 65 73 00 00 00 00 43 68 65 63 6b 45 78 65 53 69 67 6e 61 74 75 72 65 73 00 00 6e 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Trapwot_206303_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Trapwot"
        threat_id = "206303"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Trapwot"
        severity = "18"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b8 4f ec c4 4e f7 e1 c1 ea 03 6b d2 1a 2b ca 0f be 55 ff 3b ca 75}  //weight: 3, accuracy: High
        $x_1_2 = {6a 2e 51 e8 ?? ?? ?? ?? 83 c4 08 3b c7 74 ?? 8d 95 ?? ?? ?? ?? 2b c2 83 f8 0a 75 ?? 50 6a 04 6a 05 8b c2 6a 03 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 2e 50 e8 ?? ?? ?? ?? 83 c4 08 ?? ?? (0f 84 ?? ?? ?? ??|74 ??) 8d 8d ?? ?? ?? ?? 2b c1 83 f8 0a (0f 85 ?? ?? ?? ??|75 ??) 50 6a 07 6a 03 8b d1 6a 02 52 e8}  //weight: 1, accuracy: Low
        $x_3_4 = {8b 4e 10 8b 44 31 10 83 c4 0c a8 03 ba 00 00 00 00 0f 95 c2 83 e0 fc 83 c1 fc 8d 04 90 3b c1}  //weight: 3, accuracy: High
        $x_3_5 = {6a 04 68 00 30 00 00 50 6a 00 8b ?? ff 15 ?? ?? ?? ?? 89 ?? 8b 4c ?? 54 51 53 50 e8 ?? ?? ?? ?? 8b ?? 03 40 3c 08 00 [0-1] 8b ?? 3c 8b 44 ?? 50}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Trapwot_206303_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Trapwot"
        threat_id = "206303"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Trapwot"
        severity = "18"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 00 6e 00 4c 00 6f 00 61 00 64 00 65 00 64 00 00 00 00 00 73 00 74 00 6f 00 70 00 53 00 63 00 61 00 6e 00 00 00 00 00 73 00 74 00 61 00 72 00 74 00 53 00 65 00 61 00 72 00 63 00 68 00 00 00 62 00 75 00 79 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 00 63 00 61 00 6e 00 20 00 66 00 6f 00 72 00 20 00 76 00 69 00 72 00 75 00 73 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_4_3 = {70 61 72 74 74 77 6f 2e 64 6c 6c 00 45 6e 74 72 79 50 6f 69 6e 74 00}  //weight: 4, accuracy: High
        $x_1_4 = {42 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 52 00 65 00 73 00 6f 00 6c 00 76 00 65 00 72 00 00 00 53 00 65 00 53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {6f 00 70 00 65 00 6e 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 00 00 6f 00 70 00 65 00 6e 00 53 00 68 00 6f 00 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 00 74 00 6f 00 70 00 53 00 63 00 61 00 6e 00 00 00 00 00 67 00 65 00 74 00 41 00 64 00 76 00 49 00 64 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Trapwot_206303_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Trapwot"
        threat_id = "206303"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Trapwot"
        severity = "18"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = {8b 4f 10 8b 44 39 10 83 c4 0c a8 03 ba 00 00 00 00 0f 95 c2 83 e0 fc 83 c1 fc 8d 04 90 3b c1 80 3b 4d (75 ??|0f 85 ?? ?? ?? ??) 80 7b 01 5a (75|0f 85)}  //weight: 16, accuracy: Low
        $x_16_2 = {8b 4e 10 8b 44 31 10 83 c4 0c a8 03 ba 00 00 00 00 0f 95 c2 83 e0 fc 83 c1 fc 8d 04 90 3b c1 80 ?? 4d (75 ??|0f 85 ?? ?? ?? ??) 80 ?? 01 5a (75|0f 85)}  //weight: 16, accuracy: Low
        $x_16_3 = {8b 4e 10 8b 44 31 10 83 c4 0c a8 03 ba 00 00 00 00 0f 95 c2 83 e0 fc 83 c1 fc 8d 04 90 3b c1 ?? ?? ?? 55 8b ec 8b 45 08 80 38 4d [0-3] 75 ?? 80 78 01 5a}  //weight: 16, accuracy: Low
        $x_16_4 = {8b 4e 10 8b 44 31 10 83 c4 0c a8 03 ba 00 00 00 00 0f 95 c2 83 e0 fc 83 c1 fc 8d 04 90 3b c1 ?? ?? ?? 55 8b ec 8b 45 08 80 78 01 5a [0-3] 75 ?? 80 38 4d}  //weight: 16, accuracy: Low
        $x_16_5 = {8b 4e 10 8b 44 31 10 83 c4 0c a8 03 ba 00 00 00 00 0f 95 c2 83 e0 fc 83 c1 fc 8d 04 90 3b c1 ?? ?? ?? 55 8b ec 8b 45 08 [0-3] (b9|ba) 4d 5a 00 00 66 39 (08|10)}  //weight: 16, accuracy: Low
        $x_1_6 = {b8 4f ec c4 4e f7 e1 c1 ea 03 6b d2 1a 2b ca 0f be 55 ff 3b ca 75}  //weight: 1, accuracy: High
        $x_1_7 = {6a 2e 51 e8 ?? ?? ?? ?? 83 c4 08 3b c7 74 ?? 8d 95 ?? ?? ?? ?? 2b c2 83 f8 0a 75 ?? 50 6a 04 6a 05 8b c2 6a 03 50 e8}  //weight: 1, accuracy: Low
        $x_1_8 = {6a 2e 50 e8 ?? ?? ?? ?? 83 c4 08 ?? ?? (0f 84 ?? ?? ?? ??|74 ??) 8d 8d ?? ?? ?? ?? 2b c1 83 f8 0a (0f 85 ?? ?? ?? ??|75 ??) 50 6a 07 6a 03 8b d1 6a 02 52 e8}  //weight: 1, accuracy: Low
        $x_1_9 = {67 65 74 5f 74 77 6f 3f 76 3d [0-2] 26 61 3d [0-3] 26 75 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 69 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_16_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Trapwot_206303_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Trapwot"
        threat_id = "206303"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Trapwot"
        severity = "18"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b8 4f ec c4 4e f7 e1 c1 ea 03 6b d2 1a 2b ca 0f be 55 ff 3b ca 75}  //weight: 3, accuracy: High
        $x_1_2 = {6a 2e 51 e8 ?? ?? ?? ?? 83 c4 08 3b c7 74 ?? 8d 95 ?? ?? ?? ?? 2b c2 83 f8 0a 75 ?? 50 6a 04 6a 05 8b c2 6a 03 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 2e 50 e8 ?? ?? ?? ?? 83 c4 08 ?? ?? (0f 84 ?? ?? ?? ??|74 ??) 8d 8d ?? ?? ?? ?? 2b c1 83 f8 0a (0f 85 ?? ?? ?? ??|75 ??) 50 6a 07 6a 03 8b d1 6a 02 52 e8}  //weight: 1, accuracy: Low
        $x_3_4 = {8b 4e 10 8b 44 31 10 83 c4 0c a8 03 ba 00 00 00 00 0f 95 c2 83 e0 fc 83 c1 fc 8d 04 90 3b c1}  //weight: 3, accuracy: High
        $x_3_5 = {55 8b ec 8b 45 08 [0-112] b9 ?? ?? ?? ?? 66 33 08 ba ?? ?? ?? ?? 66 3b ca}  //weight: 3, accuracy: Low
        $x_3_6 = {55 8b ec 8b 45 08 ?? ?? ?? 0f b7 08 81 f1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 74}  //weight: 3, accuracy: Low
        $x_3_7 = {55 8b ec 8b 45 08 56 8b f1 0f b7 48 [0-48] ba ?? ?? ?? ?? 66 33 10 b9 ?? ?? ?? ?? 66 3b d1}  //weight: 3, accuracy: Low
        $x_3_8 = {0f b7 08 81 e9 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? (75|74)}  //weight: 3, accuracy: Low
        $x_3_9 = {0f b7 10 81 ea ?? ?? ?? ?? 81 fa ?? ?? ?? ?? (75|74)}  //weight: 3, accuracy: Low
        $x_3_10 = {55 8b ec 8b 45 08 56 8b f1 b9 [0-84] ba ?? ?? ?? ?? 66 33 10 b9 ?? ?? ?? ?? 66 3b d1}  //weight: 3, accuracy: Low
        $x_3_11 = {66 3b ca 74 ?? b9 ?? ?? ?? ?? 66 33 08 ba ?? ?? ?? ?? 66 3b ca 75 ?? b9 ?? ?? ?? ?? 66 39 48 ?? 74}  //weight: 3, accuracy: Low
        $x_3_12 = {66 3b d1 74 ?? ba ?? ?? ?? ?? 66 33 10 b9 ?? ?? ?? ?? 66 3b d1 75 ?? ba ?? ?? ?? ?? 66 39 50 ?? 74}  //weight: 3, accuracy: Low
        $x_3_13 = {66 3b ca 74 ?? ba ?? ?? ?? ?? 66 33 10 bf ?? ?? ?? ?? 66 3b d7 75 ?? ba ?? ?? ?? ?? 66 3b ca 74}  //weight: 3, accuracy: Low
        $x_3_14 = {66 3b d7 74 ?? ba ?? ?? ?? ?? 66 33 10 bf ?? ?? ?? ?? 66 3b d7 75 ?? ba ?? ?? ?? ?? 66 3b ca 74}  //weight: 3, accuracy: Low
        $x_3_15 = {66 8b 38 ba ?? ?? ?? ?? 66 2b fa ba ?? ?? ?? ?? 66 33 fa ba ?? ?? ?? ?? 66 3b fa 75}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Trapwot_206303_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Trapwot"
        threat_id = "206303"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Trapwot"
        severity = "18"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b8 4f ec c4 4e f7 e1 c1 ea 03 6b d2 1a 2b ca 0f be 55 ff 3b ca 75}  //weight: 3, accuracy: High
        $x_1_2 = {6a 2e 51 e8 ?? ?? ?? ?? 83 c4 08 3b c7 74 ?? 8d 95 ?? ?? ?? ?? 2b c2 83 f8 0a 75 ?? 50 6a 04 6a 05 8b c2 6a 03 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 2e 50 e8 ?? ?? ?? ?? 83 c4 08 ?? ?? (0f 84 ?? ?? ?? ??|74 ??) 8d 8d ?? ?? ?? ?? 2b c1 83 f8 0a (0f 85 ?? ?? ?? ??|75 ??) 50 6a 07 6a 03 8b d1 6a 02 52 e8}  //weight: 1, accuracy: Low
        $x_3_4 = {8b 4e 10 8b 44 31 10 83 c4 0c a8 03 ba 00 00 00 00 0f 95 c2 83 e0 fc 83 c1 fc 8d 04 90 3b c1}  //weight: 3, accuracy: High
        $x_1_5 = {0f b6 10 83 ea ?? 83 fa ?? (0f 85|75)}  //weight: 1, accuracy: Low
        $x_1_6 = {8a 10 80 f2 ?? 80 fa ?? (0f 85|75)}  //weight: 1, accuracy: Low
        $x_1_7 = {8a 10 80 ea ?? 80 fa ?? (0f 85|75)}  //weight: 1, accuracy: Low
        $x_1_8 = {8a 08 80 f1 ?? 80 f9 ?? (0f 85|75)}  //weight: 1, accuracy: Low
        $x_1_9 = {8a 10 80 c2 ?? 80 fa ?? (0f 85|75)}  //weight: 1, accuracy: Low
        $x_1_10 = {8a 10 80 f2 ?? 80 ea ?? 80 fa ?? (0f 85|75)}  //weight: 1, accuracy: Low
        $x_1_11 = {8a 10 80 f2 ?? 80 c2 ?? 80 fa ?? (0f 85|75)}  //weight: 1, accuracy: Low
        $x_2_12 = {0f b6 50 01 83 ea ?? 83 fa ?? (0f 85|75)}  //weight: 2, accuracy: Low
        $x_2_13 = {8a 50 01 80 f2 ?? 80 fa ?? (0f 85|75)}  //weight: 2, accuracy: Low
        $x_2_14 = {8a 50 01 80 c2 ?? 80 fa ?? (0f 85|75)}  //weight: 2, accuracy: Low
        $x_2_15 = {8a 48 01 80 e9 [0-2] 80 f9 ?? (0f 85|75)}  //weight: 2, accuracy: Low
        $x_2_16 = {8a 50 01 80 ea ?? 80 fa ?? (0f 85|75)}  //weight: 2, accuracy: Low
        $x_2_17 = {8a 50 01 80 f2 ?? 80 ea ?? 80 fa ?? (0f 85|75)}  //weight: 2, accuracy: Low
        $x_2_18 = {8a 50 01 80 f2 ?? 80 c2 ?? 80 fa ?? (0f 85|75)}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

