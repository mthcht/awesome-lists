rule Worm_Win32_Vobfus_E_2147628204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.E"
        threat_id = "2147628204"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 2e 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 74 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 68 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 65 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 69 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 6d 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 61 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 67 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 65 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 70 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 61 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 72 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 6c 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 6f 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 75 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 72 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_F_2147628592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.F"
        threat_id = "2147628592"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {4b ff ff 00 24 04 76 ff 04 78 ff 05 00 00 24 01 00 0d 14 00 02 00 08 78 ff 0d 68 00 03 00 6b 76 ff 1a 78 ff 1c 2f 00 00 04 fc c8 00 1d f4 00 04 78 ff 05 00 00 24 01 00 0d 14 00 02 00 08 78 ff 0d 7c 00 03 00 1a 78 ff 00 27 04 70 ff 04 78 ff 05 00 00 24 01 00 0d 14 00 02 00 08 78 ff 0d 60 00 03 00 3e 70 ff fd e7 08 00 ?? 00 1a 78 ff 00 20 f5 00 00 00 00 04 78 ff 05 00 00 24 01 00 0d 14 00 02 00 08 78 ff 0d 64 00 03 00 1a 78 ff}  //weight: 15, accuracy: Low
        $x_8_2 = {f4 58 fc 0d f5 00 00 00 00 04 ?? ?? ?? ?? [0-2] f4 59 fc 0d f5 01 00 00 00 04 ?? ?? ?? ?? [0-2] f4 59 fc 0d f5 02 00 00 00 04 ?? ?? ?? ?? [0-5] f4 59}  //weight: 8, accuracy: Low
        $x_5_3 = {a9 f3 00 01 c1 e7 04 60 ff 9d fb 12 fc 0d}  //weight: 5, accuracy: High
        $x_5_4 = {43 00 72 00 65 00 61 00 74 00 65 00 53 00 68 00 6f 00 72 00 74 00 63 00 75 00 74 00 00 00 00 00 (54 00 61 00 72 00 67 00 65 00 74 00 50 00 61 00 74 00|49 00 63 00 6f 00 6e 00 4c 00 6f 00 63 00 61 00 74 00 69 00 6f 00) 00}  //weight: 5, accuracy: Low
        $x_5_5 = {77 73 6f 63 6b 33 32 00 0e 00 00 00 67 65 74 68 6f 73 74 62 79 6e 61 6d 65 00}  //weight: 5, accuracy: High
        $x_5_6 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 3 of ($x_5_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_G_2147628815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.G"
        threat_id = "2147628815"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f5 47 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 6f 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 74 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 6f 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 20 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {f5 4e 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 61 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 6d 00 00 00 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 65 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {f5 58 59 59 59}  //weight: 1, accuracy: High
        $x_1_4 = {f4 58 fc 0d f5 00 00 00 00 04 ?? ?? ?? ?? [0-2] f4 59 fc 0d f5 01 00 00 00 04 ?? ?? ?? ?? [0-2] f4 59 fc 0d f5 02 00 00 00 04 ?? ?? ?? ?? [0-5] f4 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_I_2147631105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.I"
        threat_id = "2147631105"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {27 58 ff 0a 25 00 04 00 35 58 ff 00 14 f5 01 00 00 00 fb fe 23 54 ff 0a 00 00 04 00 2f 54 ff 00 0b f4 01 f4 01 0a 01 00 08 00 00 28 f5 01 00 00 00 fb fe 23 50 ff f5 01 00 00 00 fb fe 23 54 ff 04 58 ff 0a 02 00 0c 00 32 04 00 54 ff 50 ff 35 58 ff 00 25 f5 00 00 00 00 f5 00 00 00 00 04 4c ff 05 03 00 24 04 00 0d 14 00 05 00 08 4c ff 0d 38 01 06 00 1a 4c ff}  //weight: 1, accuracy: High
        $x_1_2 = "VB.DriveListBox" ascii //weight: 1
        $x_1_3 = {00 77 73 6f 63 6b 33 32 00 0e 00 00 00 67 65 74 68 6f 73 74 62 79 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {a9 f3 00 01 c1 e7 04 60 ff 9d fb 12 fc 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_M_2147631417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.M"
        threat_id = "2147631417"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 ec f2 34 6c ec f2 6c 68 ff 5e ?? 00 08 00 71 18 f7 3c 6c ec f2 05 ?? 00 fc 58 6c 18 f7 71 74 ff 2f ec f2 00 29 76 ?? 00 04 ec f2 34 6c ec f2 6c 68 ff 5e ?? 00 08 00 71 18 f7 3c 6c ec f2 05 ?? 00 fc 58 6c 18 f7 71 40 f7 2f ec f2 00 0e 6c 74 ff f5 00 00 00 00 cc 1c 93 05 00 84 f3 c3 00 2b d2 f2 5e ?? 00 04 00 71 14 f7 04 18 f7 f5 00 00 00 00 f5 04 00 00 00 04 3c f7 fe 8e 01 00 00 00 10 00 80 08}  //weight: 1, accuracy: Low
        $x_1_2 = {00 04 00 00 08 6c 74 ff 43 6c ff 00 0a 6c 6c ff 4a e4 70 70 ff 00 13 f4 01 04 72 ff 6b 70 ff f4 01 ad fe 63 44 ff 7d 00 00 1e 04 42 ff 04 70 ff 04 72 ff 10 ?? 07 ?? 00 6b 42 ff 6b 72 ff 04 6c ff 10 ?? 07 ?? 00 00 0a 04 72 ff 64 44 ff 55 00 00 08}  //weight: 1, accuracy: Low
        $x_1_3 = {a9 f3 00 01 c1 e7 04 60 ff 9d fb 12 fc 0d}  //weight: 1, accuracy: High
        $x_1_4 = {77 73 6f 63 6b 33 32 00 0e 00 00 00 67 65 74 68 6f 73 74 62 79 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {6b 65 72 6e 65 6c 33 32 00 00 00 00 0d 00 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 57 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_N_2147631772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.N"
        threat_id = "2147631772"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b9 58 00 00 00 ff 15 ?? ?? 40 00 8b 4d d0 03 8d 2c ff ff ff 88 01 c7 45 fc 04 00 00 00 c7 85 2c ff ff ff 01 00 00 00 83 bd 2c ff ff ff 41 73}  //weight: 5, accuracy: Low
        $x_5_2 = {b9 59 00 00 00 ff 15 ?? ?? 40 00 8b 55 d0 03 95 2c ff ff ff 88 02 c7 45 fc 05 00 00 00 c7 85 2c ff ff ff 02 00 00 00 83 bd 2c ff ff ff 41 73}  //weight: 5, accuracy: Low
        $x_5_3 = {b9 50 00 00 00 ff 15 ?? ?? 40 00 8b 55 d0 03 95 2c ff ff ff 88 02 c7 45 fc 09 00 00 00 c7 45 b8 06 00 00 00 c7 45 fc 0a 00 00 00}  //weight: 5, accuracy: Low
        $x_1_4 = {77 73 32 5f 33 32 00 00 0e 00 00 00 67 65 74 68 6f 73 74 62 79 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_O_2147631936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.O"
        threat_id = "2147631936"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {82 f4 c4 49 20 00 01 00 48 1d 90 49 2d 00 00 00 86 a1 02 48 37 00 00 00 00 00 00 00 00 00 00 00 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 4e 54 44 4c 4c 2e 44 4c 4c 00 4d 53 56 42 56 4d 36 30 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_2 = {0e 00 00 00 50 72 6f 63 65 73 73 33 32 4e 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {0e 00 00 00 67 65 74 68 6f 73 74 62 79 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {fe 8e 01 00 00 00 10 00 80 08 28 ?? ?? 00 00 f5 00 00 00 00 6c ?? ?? 52 28 ?? ?? 00 00 f5 01 00 00 00 6c ?? ?? 52 6c ?? ?? fd 69 ?? ?? f5 02 00 00 00 6c ?? ?? 52 28 ?? ?? 00 00 f5 03 00 00 00 6c ?? ?? 52 28 ?? ?? 00 00 f5 04 00 00 00 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_A_2147636661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!A"
        threat_id = "2147636661"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f4 02 eb 6b ?? ff eb fb cf e8 c4 f5 00 00 00 00 cc 1c}  //weight: 1, accuracy: Low
        $x_1_2 = {f4 02 eb 6b 72 ff eb fb cf e8 c4 e4 f4 00 cb 1c}  //weight: 1, accuracy: High
        $x_1_3 = {a9 f3 00 01 c1 e7 04 60 ff 9d fb 12 fc 0d}  //weight: 1, accuracy: High
        $x_1_4 = {f5 19 02 00 00 c7 1c 80 01 f5 (04 80|00 80) c7 1c}  //weight: 1, accuracy: Low
        $x_1_5 = {5b 00 00 00 04 64 ff 0a 16 00 08 00 04 64 ff f5 61 00 00 00 04 54 ff 0a 16 00 08 00 04 54 ff fb ef 44 ff f5 75 00 00 00 04 34 ff 0a 16 00 08 00 04 34 ff fb ef 24 ff f5 74}  //weight: 1, accuracy: High
        $x_1_6 = {f5 2e 00 00 00 04 5c fd 0a 0a 00 08 00 04 5c fd fb ef 4c fd f5 63 00 00 00 04 3c fd 0a 0a 00 08 00 04 3c fd fb ef 2c fd f5 6e 00 00 00 04 1c fd 0a 0a 00 08 00 04 1c fd fb ef 0c fd f5 2f}  //weight: 1, accuracy: High
        $x_1_7 = {f5 2e 00 00 00 0b ?? ?? 04 00 23 ?? ff 2a 23 ?? ff f5 73 00 00 00 0b ?? ?? 04 00 23 ?? ff 2a 23 ?? ff f5 63 00 00 00 0b ?? ?? 04 00 23 ?? ff 2a 46 ?? ff f5 72}  //weight: 1, accuracy: Low
        $x_1_8 = {f5 6b 00 00 00 0b ?? 00 04 00 31 ?? ?? f5 65 00 00 00 0b ?? 00 04 00 31 ?? ?? f5 72 00 00 00 04 ?? ?? 0a ?? 00 08 00 f5 6e}  //weight: 1, accuracy: Low
        $x_1_9 = {f5 05 00 00 00 ae 71 6c ff 02 00 f5 38 00 00 00 04 ?? ff 0a ?? 00 08 00 04 ?? ff f5 42 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Vobfus_B_2147636701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!B"
        threat_id = "2147636701"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 3c 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 50 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 41 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 54 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 43 00 00 00 0b ?? ?? ?? ?? 46 ?? ?? fb ef ?? ?? f5 48 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {f5 3c 00 00 00 0b ?? ?? ?? ?? 46 ?? ?? fb ef ?? ?? f5 50 00 00 00 0b ?? ?? ?? ?? 46 ?? ?? fb ef ?? ?? f5 41 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 54 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 43 00 00 00 0b ?? ?? ?? ?? 46 ?? ?? fb ef ?? ?? f5 48 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 00 00 00 00 f5 40 00 00 00 3e ?? ?? 46 ?? ?? 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? 60 31 ?? ?? 2f ?? ?? 36 ?? ?? ?? ?? ?? ?? 00 ?? 1b [0-5] f4 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Vobfus_C_2147636886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!C"
        threat_id = "2147636886"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a f5 02 00 00 00 b2 aa f5 02 00 00 00 aa 6c ?? ff 0b ?? 00 0c 00 31 ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 00 01 c1 e7 04 ?? ff 9d fb 12 fc 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {fb 12 fc 0d 6c ?? ?? 80 ?? ?? fc a0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_D_2147637688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!D"
        threat_id = "2147637688"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 6b 00 00 00 0b ?? 00 04 00 31 ?? ?? f5 65 00 00 00 0b ?? 00 04 00 31 ?? ?? f5 72 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {f4 02 eb 6b ?? ff eb fb cf e8 c4 [0-10] f5 00 00 00 00 ?? 1c}  //weight: 1, accuracy: Low
        $x_1_3 = {f4 02 eb 6b ?? ff eb fb cf e8 c4 e4 70 ?? ff ?? ?? 6b ?? ff f4 00 cb 1c}  //weight: 1, accuracy: Low
        $x_1_4 = {f4 02 eb 6b 72 ff eb fb cf e8 c4 fb fe 23 4c ff 50 71 48 ff 2f 4c ff 00 0e 6c 48 ff f5 00 00 00 00 cc}  //weight: 1, accuracy: High
        $x_1_5 = {f4 02 eb 6b 74 ff eb fb cf e8 c4 fd 69 ?? ?? fc 46 71 ?? ?? 00 0e 6c ?? ?? f5 00 00 00 00 cc 1c}  //weight: 1, accuracy: Low
        $x_1_6 = {f5 70 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef 34 ff f5 6c 00 00 00 0b ?? 00 04 ?? ?? 0c ff fb ef fc fe f5 61 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef dc fe f5 79}  //weight: 1, accuracy: Low
        $x_1_7 = {c1 e7 04 60 ff 9d 04 00 a9}  //weight: 1, accuracy: Low
        $x_1_8 = {4a ec fd c9 ?? ?? 6c 58 ff ec 39 04 ?? ff 0a ?? ?? ?? ?? f3 00 01 eb fd}  //weight: 1, accuracy: Low
        $x_1_9 = {f5 53 00 00 00 0b ?? 00 04 00 46 40 ff f5 63 00 00 00 04 50 ff 0a ?? ?? ?? ?? 04 50 ff fb ef 30 ff f5 72 00 00 00 0b ?? 00 04 00 46 20 ff fb ef 10 ff f5 69 00 00}  //weight: 1, accuracy: Low
        $x_1_10 = {fd 16 10 00 4c ff fb 27 3c ff fb c4 2c ff fc f6 6c ff}  //weight: 1, accuracy: High
        $x_1_11 = {f5 19 02 00 00 (c7 1c|e4 e7 c7 1c) 00 02 f5 00 80 00 00 c7 1c}  //weight: 1, accuracy: Low
        $x_1_12 = {b3 7f 0c 00 eb ab fb e6 e5 04 00 eb 6e ?? ff}  //weight: 1, accuracy: Low
        $x_1_13 = {eb b3 fb e6 7f 0c 00 eb ab e5}  //weight: 1, accuracy: High
        $x_1_14 = {e7 aa f5 00 01 00 00 c2 07 00 4a c2 6c ?? ff fc 90}  //weight: 1, accuracy: Low
        $x_1_15 = {4a c2 6c 4c ff fc 90 e7 aa 6b 42 ff e7 c2}  //weight: 1, accuracy: High
        $x_1_16 = {fe fd fc 52 1c 08 00 1b ?? 00 f5 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_17 = {f4 58 fc 0d [0-10] f4 5b fc 0d 01 80 f4 50 fc 0d 02 30 f3 c3 00 fc 0d}  //weight: 1, accuracy: Low
        $x_1_18 = {f4 58 fc 0d 0a ?? ?? ?? ?? ?? ?? 1b [0-255] f4 5b fc 0d 0a [0-10] f4 50 fc 0d 0a 03 50 f3 c3 00 fc 0d}  //weight: 1, accuracy: Low
        $x_1_19 = {fd e7 08 00 94 00 1a ?? ?? 00 07 0a ?? 00 00 00 00 27 04 78 ff 04 ?? ?? 05 ?? 00 24 ?? 00 0d 14 00 ?? 00 08 ?? ?? 0d 58 00 ?? 00 3e 78 ff fd e7 08 00 f0 00 1a ?? ?? 00 36 94 08 00 f0 00 1b ?? 00 1b}  //weight: 1, accuracy: Low
        $x_1_20 = {1b 31 00 2a 23 0c ff 1b 0c 00 2a 23 08 ff 1b 16 00 2a 23 04 ff 1b 12 00 2a 23 00 ff 1b 39 00 2a 23 fc fe 1b 3a 00 2a 23 f8 fe 1b 3b 00 2a 23 f4 fe 1b 0e 00 2a 23 f0 fe 1b 3c 00}  //weight: 1, accuracy: High
        $n_100_21 = "\\\\MAPLEWOOD,\\\\MWOOD" wide //weight: -100
        $n_100_22 = "\\DynaTouch" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule Worm_Win32_Vobfus_Y_2147637813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.Y"
        threat_id = "2147637813"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f4 02 eb 6b 74 ff eb fb cf e8 c4 f5 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {80 10 00 04 ?? ff 34 6c ?? ff 08 ?? ?? 0d ?? 00 ?? ?? 6c ?? ff 6c 10 00 fc 58 2f ?? ff 00 23 6b 6e ff e7 6c 68 ff 04 ?? ff 34 6c ?? ff 08 ?? ?? 0d ?? 00 ?? ?? 6c ?? ff 04 68 ff fc 58 2f ?? ff 00 1f 6c 64 ff 04 ?? ff 34 6c ?? ff 08 ?? ?? 0d ?? 00 ?? ?? 6c ?? ff 04 64 ff fc 58}  //weight: 1, accuracy: Low
        $x_1_3 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46}  //weight: 1, accuracy: High
        $x_1_4 = "vb.drivelistbox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_Z_2147637924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.Z"
        threat_id = "2147637924"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 2e 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 63 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 6f 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 64 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 65 00 00 00 0b ?? ?? ?? ?? 46 ?? ?? fb ef ?? ?? f5 63 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {f5 64 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 65 00 00 00 0b ?? ?? ?? ?? 46 ?? ?? fb ef ?? ?? f5 63 00 00 00 0b ?? ?? ?? ?? 46 ?? ?? fb ef ?? ?? f5 6f 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 6e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 70 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 6c 00 00 00 0b ?? ?? ?? ?? 46 ?? ?? fb ef ?? ?? f5 61 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 79 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Vobfus_AB_2147638284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.AB"
        threat_id = "2147638284"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1b ce 00 2a 23 ?? ?? 1b cf 00 2a 23 ?? ?? 1b d0 00 2a 23 ?? ?? 1b d1 00 2a 23 ?? ?? 1b ce 00 2a 23 ?? ?? 1b cf 00 2a 23 ?? ?? 1b d2 00 2a 23 ?? ?? 1b d3 00 2a 23 ?? ?? 1b d4 00 2a 23 ?? ?? 1b d2 00 2a 23 ?? ?? 1b d1 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_AC_2147638390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.AC"
        threat_id = "2147638390"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a f5 02 00 00 00 b2 aa f5 02 00 00 00 aa 6c ?? ff 0b ?? 00 0c 00 31 ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {f4 02 eb 6b ?? ff eb fb cf e8 c4 f5 00 00 00 00 ?? 1c}  //weight: 1, accuracy: Low
        $x_1_3 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46}  //weight: 1, accuracy: High
        $x_1_4 = {fe 8e 01 00 00 00 10 00 80 08 28 ?? ?? 00 00 f5 00 00 00 00 6c ?? ?? 52 28 ?? ?? 00 00 f5 01 00 00 00 6c ?? ?? 52 6c ?? ?? fd 69 ?? ?? f5 02 00 00 00 6c ?? ?? 52 28 ?? ?? 00 00 f5 03 00 00 00 6c ?? ?? 52 28 ?? ?? 00 00 f5 04 00 00 00 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_AD_2147638539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.AD"
        threat_id = "2147638539"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7a 00 00 00 02 00 00 00 20 00 00 00 02 00 00 00 31 00 00 00 02 00 00 00 63 00 00 00 02 00 00 00 6f 00 00 00 02 00 00 00 64 00 00 00 02 00 00 00 65 00 00 00 02 00 00 00 6c 00 00 00 02 00 00 00 69 00 00 00 02 00 00 00 2e 00 00 00 02 00 00 00 62 00 00 00 02 00 00 00 70 00 00 00 02 00 00 00 79 00 00 00 02 00 00 00 72 00 00 00 02 00 00 00 35 00 00 00 02 00 00 00 32 00 00 00 02 00 00 00 33 00 00 00 02 00 00 00 6d 00 00 00 02 00 00 00 4e 00 00 00 02 00 00 00 57 00 00 00 02 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {0d 14 00 0c 00 08 00 ff 0d 58 00 0d 00 3e 44 ff 31 78 ff 1a 00 ff 00 34 6c 78 ff 1b ?? ?? 1b ?? ?? 2a 23 44 ff 1b ?? ?? 2a 23 f8 fe 1b ?? ?? 2a 23 f4 fe 1b ?? ?? 2a 23 f0 fe fb 30 32}  //weight: 1, accuracy: Low
        $x_1_3 = {04 48 ff 04 44 ff 05 ?? ?? 24 ?? ?? 0d 14 00 1a 00 08 44 ff 0d 58 00 1b 00 04 ?? ?? 10 38 00 14 00 04 ?? ?? f4 01 2b 3e ff 10 64 00 14 00 04 ?? ?? 6c 40 ff 1b ?? ?? 2a 23 34 ff 6c 38 ff 2a fd c7 2c ff 6c 48 ff 76 50 00 f5 01 00 00 80 59 30 ff 10 20 00 14 00 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_AH_2147638656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.AH"
        threat_id = "2147638656"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 ff fd b6 ?? 00 00 [0-16] 8e 76 ?? 00 1b ?? ?? 2a 23 ?? ?? 1b ?? ?? 2a 23 ?? ?? 1b ?? ?? 2a 23 ?? ?? 1b ?? ?? 2a 23 ?? ?? 1b ?? ?? 2a 23 ?? ?? 1b ?? ?? 2a 23 ?? ?? 1b ?? ?? 2a 23}  //weight: 1, accuracy: Low
        $x_1_2 = {63 00 00 00 02 00 00 00 6f 00 00 00 02 00 00 00 64 00 00 00 02 00 00 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 00 00 00 02 00 00 00 62 00 00 00 [0-8] 02 00 00 00 70 00 00 00 02 00 00 00 61 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {7a 00 00 00 02 00 00 00 20 00 00 00 02 00 00 00 31 00 00 00 02 00 00 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 00 00 00 [0-8] 02 00 00 00 4d 00 00 00 02 00 00 00 46 00 00 00 02 00 00 00 4e 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Vobfus_AJ_2147638763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.AJ"
        threat_id = "2147638763"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46}  //weight: 1, accuracy: High
        $x_1_2 = {04 1c ff 05 ?? 00 24 ?? 00 0d ?? 00 ?? ?? 08 ?? ?? 0d ?? 00 [0-10] 6c ?? ?? 2a 23 ?? ?? 1b ?? ?? 2a 23 ?? ?? 94 ?? ?? ?? ?? 2a fd c7}  //weight: 1, accuracy: Low
        $x_1_3 = {6c 78 ff 1b ?? ?? 1b ?? ?? 2a 23 ?? ?? 1b ?? ?? 2a 23 ?? ?? 1b ?? ?? 2a 23 ?? ?? 1b ?? ?? 2a 23 ?? ?? fb 30 32 08 00}  //weight: 1, accuracy: Low
        $x_3_4 = {47 00 00 00 02 00 00 00 74 00 00 00 02 00 00 00 4d 00 00 00 02 00 00 00 64 00 00 00 02 00 00 00 46 00 00 00 02 00 00 00 69 00 00 00 02 00 00 00 4e 00 00 00 02 00 00 00 61 00 00 00 02 00 00 00 6d 00 00 00 02 00 00 00 57 00 00 00 04 00 00 00 20 00 2f 00 00 00 00 00 02 00 00 00 7a 00 00 00 02 00 00 00 31 00 00 00 02 00 00 00 63 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_E_2147641663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!E"
        threat_id = "2147641663"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {04 50 ff f3 c3 00 fc 0d}  //weight: 2, accuracy: High
        $x_1_2 = {3c 00 00 00 59 01 00 00 04 29 00 00 1f 1d}  //weight: 1, accuracy: High
        $x_1_3 = {3c 00 00 00 59 01 00 00 c0 30 00 00 c8 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_AW_2147642664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.AW"
        threat_id = "2147642664"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46}  //weight: 1, accuracy: High
        $x_1_2 = {f3 e7 03 2b ?? ?? f4 01 2b ?? ?? 0b ?? 00 ?? ?? ?? ?? 23 ?? ?? 2a 23 ?? ?? 1b ?? 00 2a 23 ?? ?? 1b ?? 00 2a 23 ?? ?? 1b ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 28 00 00 00 0b ?? ?? ?? ?? 23 ?? ?? f5 5c 00 00 00 0b ?? ?? ?? ?? 23 ?? ?? 2a 23 ?? ?? 0b ?? ?? 00 00 23 ?? ?? 2a 23 ?? ?? 94 08 00 7c 00 2a}  //weight: 1, accuracy: Low
        $x_1_4 = {07 08 00 04 00 52 [0-6] 1b ?? 00 1b ?? 00 2a 23 ?? ?? 1b ?? 00 2a fd ?? 08 ?? ?? ?? 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Vobfus_AX_2147642787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.AX"
        threat_id = "2147642787"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 54 ff 67 00 fd f0 08 00 20 00 00 89 94 08 00 c8 01 1b 16 00 2a 23 30 ff 1b 14 00 2a 23 24 ff 1b 12 00 2a 23 20 ff 1b 72 00 2a 23 1c ff 1b 73 00 2a 23 18 ff 1b 74 00 2a 23 14 ff 1b 71 00 2a 23 10 ff 1b 75 00 2a 23 0c ff 1b 76 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_BF_2147643543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.BF"
        threat_id = "2147643543"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46}  //weight: 5, accuracy: High
        $x_5_2 = {f4 02 eb 6b 74 ff eb fb cf e8 c4 71 ?? ff}  //weight: 5, accuracy: Low
        $x_1_3 = {80 10 00 04 2c ff 34 6c 2c ff 08 78 ff 0d 50 00 ?? 01 6c 2c ff 6c 10 00 fc 58 2f 2c ff 00 [0-22] 6b 6e ff e7 6c 68 ff 04 2c ff 34 6c 2c ff 08 78 ff 0d 44 00 ?? 01 6c 2c ff 04 68 ff fc 58 2f 2c ff}  //weight: 1, accuracy: Low
        $x_1_4 = {80 10 00 04 2c ff 34 6c 2c ff 08 78 ff 0d 50 00 ?? 01 6c 2c ff 6c 10 00 fc 58 2f 2c ff 00 26 f5 c8 5c 00 00 07 08 00 04 00 40 04 44 ff 0a 17 00 08 00 04 44 ff f5 05 2a 00 00 07 08 00 04 00 52 35 44 ff 00 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_BI_2147643696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.BI"
        threat_id = "2147643696"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 02 00 00 00 6a ff e8 ?? ?? ?? ?? c7 45 fc 03 00 00 00 ff 75 b8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 b4 8d 45 ac 50 e8 ?? ?? ?? ?? 50 ff 75 d8 e8 ?? ?? ?? ?? 89 45 88 ff 75 ac 8d 45 b4 50 e8 ?? ?? ?? ?? 8b 45 88 89 45 d4 8d 4d ac e8 ?? ?? ?? ?? c7 45 fc ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_F_2147643991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!F"
        threat_id = "2147643991"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 c0 aa 00 00 00 0f ?? ?? ?? ?? ?? 99 b9 bb c0 c0 00 f7 f9}  //weight: 5, accuracy: Low
        $x_5_2 = {69 c0 ac 00 00 00 0f ?? ?? ?? ?? ?? 99 b9 ef 82 be 00 f7 f9}  //weight: 5, accuracy: Low
        $x_5_3 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46}  //weight: 5, accuracy: High
        $x_1_4 = {50 66 b9 50 00 e8}  //weight: 1, accuracy: High
        $x_1_5 = {50 66 b9 58 00 e8}  //weight: 1, accuracy: High
        $x_1_6 = {50 66 b9 5b 00 e8}  //weight: 1, accuracy: High
        $x_1_7 = {c7 45 fc 06 00 00 00 8b 45 14 dd 45 d8 dc 20 dd 5d d8 df e0 a8 0d}  //weight: 1, accuracy: High
        $x_1_8 = {c7 45 fc 0c 00 00 00 8b 45 14 dd 45 d8 dc 00 dd 5d d8 df e0 a8 0d 0f}  //weight: 1, accuracy: High
        $x_1_9 = {51 b9 50 00 00 00 ff}  //weight: 1, accuracy: High
        $x_1_10 = {51 b9 58 00 00 00 ff}  //weight: 1, accuracy: High
        $x_1_11 = {51 b9 5b 00 00 00 ff}  //weight: 1, accuracy: High
        $x_5_12 = {8b 55 0c 66 8b 02 66 05 01 00 0f ?? ?? ?? ?? ?? 8b 4d 08 66 2b 01 0f}  //weight: 5, accuracy: Low
        $x_3_13 = {8b 48 08 69 c9 ac 00 00 00 0f}  //weight: 3, accuracy: High
        $x_3_14 = {8b 51 08 69 d2 ac 00 00 00 0f}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_BQ_2147644465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.BQ"
        threat_id = "2147644465"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 55 84 8b 85 2c ff ff ff c1 e0 04 8b 0d ?? ?? ?? ?? 03 c8 ff 15 ?? ?? 40 00 c7 45 fc 1a 00 00 00 e8 ?? ?? 03 00 c7 45 fc 1b 00 00 00 e8 ?? ?? 02 00 c7 45 fc 1c 00 00 00 c7 45 8c 24 51 40 00 c7 45 84 08 00 00 00 c7 85 2c ff ff ff 6f 44 00 00 81 bd 2c ff ff ff 61 ea 00 00 73 0c c7 85 94 fe ff ff 00 00 00 00 eb 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_G_2147644669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!G"
        threat_id = "2147644669"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 5f 76 62 61 56 61 72 54 73 74 45 71 [0-4] 5f 5f 76 62 61 47 65 6e 65 72 61 74 65 42 6f 75 6e 64 73 45 72 72 6f 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {73 0c c7 85 1e 00 c7 85 ?? ?? ff ff ?? ?? ?? ?? c7 85 ?? ?? ff ff ?? ?? ?? ?? 81 bd 03 ff ff ?? ?? ?? ?? 73 0c c7 85 ?? ?? ff ff 00 00 00 00 eb 0c ff 15 ?? ?? ?? ?? 89 85 ?? ?? ff ff 8d 95 01 ff ff 8b 8d 03 ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e1 04 8b 15 ?? ?? ?? ?? 03 d1 8b 85 ?? ?? ff ff c1 e0 04 8b 0d ?? ?? ?? ?? 03 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_I_2147645535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!I"
        threat_id = "2147645535"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 05 00 00 00 c7 45 9c 01 00 00 00 c7 45 fc 06 00 00 00 8b 4d 08 8b 11 52 8b 4d 9c ff 15 ?? ?? ?? ?? 50 6a ff 68 20 01 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46}  //weight: 1, accuracy: High
        $x_1_3 = {5b 00 00 00 02 00 00 00 5d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 6a 01 6a 01 6a 00 8d 17 00 c7 45 fc ?? 00 00 00 66 c7 05 ?? ?? ?? ?? ff ff c7 45 fc ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = "VB.Frame" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_J_2147645847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!J"
        threat_id = "2147645847"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46}  //weight: 5, accuracy: High
        $x_5_2 = {8b d0 8d 4d d0 ff 15 ?? ?? ?? ?? 50 8b 4d dc ff 15 ?? ?? ?? ?? 50 6a ff 68 20 01 00 00 ff 15 1a 00 c7 45 fc ?? 00 00 00 c7 45 dc ?? 00 00 00 c7 45 fc ?? 00 00 00 e8}  //weight: 5, accuracy: Low
        $x_5_3 = {68 00 00 00 40 6a 00 ff 15 ?? ?? 40 00 ff 15 ?? ?? 40 00 38 00 0f bf ?? dc 89 [0-5] db [0-5] dd ?? ?? ff ff ff 8b ?? ?? ff ff ff ?? 8b ?? ?? ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_CF_2147646248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.CF"
        threat_id = "2147646248"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ff 92 00 01 00 00 db e2 89 45 ?? 83 7d ?? 00 7d 20 68 00 01 00 00 68 ?? ?? ?? 00 8b 4d ?? 51 8b 55 ?? 52 ff 15 ?? ?? 40 00 89 85 ?? ff ff ff eb 0a c7 85 ?? ff ff ff 00 00 00 00 8b 45 ?? 89 45 ?? 8d 4d ?? ff 15 ?? ?? 40 00 c7 45 fc 05 00 00 00 8b 55 ?? 8d 4d ?? ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_5_2 = {2b 48 14 c1 e1 04 8b 85 ?? ff ff ff 8b 40 0c 03 c8 ff 15 ?? ?? 40 00 8d 8d ?? ?? ff ff 51 8b 15 ?? ?? ?? 00 52 a1 ?? ?? ?? 00 50 e8 ?? ?? ?? ?? 89 85 ?? ?? ff ff 8d 8d ?? ?? ff ff 51 6a 00 ff 15 ?? ?? 40 00}  //weight: 5, accuracy: Low
        $x_1_3 = {ff ff 02 00 00 00 8d 95 ?? ?? ff ff 8b 8d ?? ?? ff ff b8 06 00 00 00 2b 41 14 c1 e0 04 8b 8d ?? ?? ff ff 8b 49 0c 03 c8 ff 15 ?? ?? 40 00 8d 95 ?? ?? ff ff 52 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_4 = {ff ff 02 00 00 00 8d 95 ?? ?? ff ff 8b 4d ?? b8 06 00 00 00 2b 41 14 c1 e0 04 8b 4d ?? 8b 49 0c 03 c8 ff 15 ?? ?? 40 00 8d 55 ?? 52 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_K_2147646571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!K"
        threat_id = "2147646571"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a f5 02 00 00 00 b2 aa f5 02 00 00 00 aa 6c ?? ff 0b ?? 00 0c 00 31 ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {f4 02 eb 6b 74 ff eb fb cf e8 c4 fd 69 ?? ?? fc 46 71 ?? ?? 00 0e 6c ?? ?? f5 00 00 00 00 cc 1c}  //weight: 1, accuracy: Low
        $x_1_3 = {f4 58 fc 0d [0-10] f4 5b fc 0d 01 80 f4 50 fc 0d 02 30 f3 c3 00 fc 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_CI_2147646799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.CI"
        threat_id = "2147646799"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 2e 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 70 e8 ?? ?? ?? ?? 89 85 [0-14] c7 85 [0-18] c7 85 [0-18] c7 85 [0-18] 6a 65}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 2e 8d 45 ?? 50 e8 ?? ?? ?? ?? c7 85 [0-18] 6a 69 e8 ?? ?? ?? ?? 89 85 [0-14] 6a 64 e8 ?? ?? ?? ?? 89 85 [0-14] 6a 65}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 74 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 61 e8 ?? ?? ?? ?? 89 85 [0-14] 6a 73 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Vobfus_CJ_2147646852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.CJ"
        threat_id = "2147646852"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 03 00 00 00 6a 00 6a 04 6a 01 6a 00 8d 45 b0 50 6a 10 68 80 08 00 00 ff 15 ?? ?? ?? ?? 83 c4 1c c7 45 a8 ?? ?? ?? ?? c7 45 a0 03 40 00 00 8d 55 a0 8b 4d b0 33 c0 2b 41 14 c1 e0 04 8b 4d b0 8b 49 0c 03 c8 ff 15 ?? ?? ?? ?? 8d 55 08 89 55 98 c7 45 90 03 40 00 00 8d 55 90 8b 45 b0 b9 01 00 00 00 2b 48 14 c1 e1 04 8b 45 b0 8b 40 0c 03 c8 ff 15 ?? ?? ?? ?? 8d 4d 0c 89 4d 88 c7 45 80 03 40 00 00 8d 55 80 8b 45 b0 b9 02 00 00 00 2b 48 14 c1 e1 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_CL_2147647019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.CL"
        threat_id = "2147647019"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 2e 8d 95 ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 63 ff 15 [0-20] 6a 6f ff 15 [0-20] 6a 6d}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 76 ff 15 [0-20] 6a 69 [0-7] ff 15 ?? ?? ?? ?? 6a 64 [0-7] ff 15 ?? ?? ?? ?? 6a 65}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 6c 8d 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 2e [0-7] ff 15 ?? ?? ?? ?? 6a 6f ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Vobfus_L_2147647673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!L"
        threat_id = "2147647673"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c0 aa 00 00 00 0f 80 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? db 85}  //weight: 2, accuracy: Low
        $x_2_2 = {69 c0 ac 00 00 00 0f 80 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? db 85}  //weight: 2, accuracy: Low
        $x_1_3 = {50 66 b9 58 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {50 66 b9 5b 00 e8}  //weight: 1, accuracy: High
        $x_1_5 = {50 66 b9 50 00 e8}  //weight: 1, accuracy: High
        $x_1_6 = {50 66 b9 c3 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_M_2147648292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!M"
        threat_id = "2147648292"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 c0 aa 00 00 00 0f 80 ?? ?? ?? ?? 89 45 ?? c7 45 ?? 05 00 00 00 dd 05 ?? ?? ?? ?? 51 51}  //weight: 5, accuracy: Low
        $x_5_2 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46}  //weight: 5, accuracy: High
        $x_1_3 = {50 66 b9 50 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {50 66 b9 58 00 e8}  //weight: 1, accuracy: High
        $x_1_5 = {50 66 b9 5b 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_N_2147649039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!N"
        threat_id = "2147649039"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c8 8b d6 e8 ?? ?? ?? ?? 8d 45 ?? 89 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 03 40 00 00 8d b5 ?? ?? ?? ?? 6a 08 ff (75 ??|b5 ?? ?? ?? ??) e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? 8d (45 ??|85 ?? ?? ?? ??) 50 ff (75 ??|35 ?? ?? ?? ??) ff (75 ??|35 ?? ?? ?? ??) e8 ?? ?? ?? ?? 8d (45 ??|85 ?? ?? ?? ??) 50 6a 00 e8}  //weight: 5, accuracy: Low
        $x_2_2 = {83 c4 1c 8b 45 08 ff 30 e8 ?? ?? ?? ?? 89 45 ?? c7 45 ?? 03 00 00 00 8d 75 ?? 6a 00 ff 75 ?? e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? 8d 45 ?? 50 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d 45 ?? 50 6a 00 e8}  //weight: 2, accuracy: Low
        $x_2_3 = {83 c4 1c 8b 45 08 ff 30 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 03 00 00 00 8d b5 ?? ?? ?? ?? 6a 00 ff b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 6a 00 e8}  //weight: 2, accuracy: Low
        $x_2_4 = {83 c4 1c 8b 45 08 ff 30 e8 ?? ?? ?? ?? 89 45 ?? c7 85 ?? ?? ?? ?? 03 00 00 00 8d b5 ?? ?? ?? ?? 6a 00 ff 75 ?? e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? 8d 45 ?? 50 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d 45 ?? 50 6a 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_DE_2147649108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.DE"
        threat_id = "2147649108"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Bearshare\\Shared\\kespersky Keys Generator.exee" wide //weight: 1
        $x_1_2 = "autorun.inf" wide //weight: 1
        $x_1_3 = "select *  from moz_logins" wide //weight: 1
        $x_1_4 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_5 = "Messanger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_DG_2147649737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.DG"
        threat_id = "2147649737"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 6a 8b 55 f4 52 e8 ?? ?? ?? ?? 83 c4 08 8b 4d 08 03 4d f8 88 01 83 7d f8 40 7d 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {52 6a 00 6a 00 68 d0 2e 40 00 6a 00 6a 00 ff 55 f4 89 45 f8 e9 c2 fe ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 6a 0d 8b 45 fc 50 68 34 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_O_2147650517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!O"
        threat_id = "2147650517"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e0 04 8b 4d ?? 8b 49 ?? 03 c8 ff 15 ?? ?? ?? ?? 8d 55 ?? 52 a1 ?? ?? ?? ?? 50 8b 0d ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d 55 ?? 52 6a 00 ff 15 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 89 45}  //weight: 2, accuracy: Low
        $x_2_2 = {c1 e1 04 8b 45 ?? 8b 40 ?? 03 c8 ff 15 ?? ?? ?? ?? 8d 4d ?? 51 8b 15 ?? ?? ?? ?? 52 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d 4d ?? 51 6a 00 ff 15 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 89 55}  //weight: 2, accuracy: Low
        $x_2_3 = {c1 e1 04 8b 45 ?? 8b 40 ?? 03 c8 ff 15 ?? ?? ?? ?? 8d 4d ?? 51 8d 55 ?? 52 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 50 8b 0d ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d 55 ?? 52 6a 00 ff 15 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 89 45}  //weight: 2, accuracy: Low
        $x_2_4 = {c1 e0 04 8b 8d ?? ?? ?? ?? 8b 49 ?? 03 c8 ff 15 ?? ?? ?? ?? 8d 95 ?? ?? ?? ?? 52 8b 45 ?? 50 8d 4d ?? 51 8d 95 ?? ?? ?? ?? 52 ff 15 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 6a 00 ff 15 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 89 4d}  //weight: 2, accuracy: Low
        $x_10_5 = {c1 e0 04 8b 4d ?? 8b 49 ?? 03 c8 ff 15 ?? ?? ?? ?? 8d 55 ?? 52 a1 ?? ?? ?? ?? 50 8b 0d ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 8d 55 ?? 52 6a 00 ff 15}  //weight: 10, accuracy: Low
        $x_10_6 = {c1 e1 04 8b 45 ?? 8b 40 ?? 03 c8 ff 15 ?? ?? ?? ?? 8d 4d ?? 51 8b 15 ?? ?? ?? ?? 52 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 4d ?? 51 6a 00 ff 15}  //weight: 10, accuracy: Low
        $x_1_7 = {c3 00 8d 55 04 00 66 c7 45}  //weight: 1, accuracy: Low
        $x_1_8 = {b9 a4 00 00 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ff ff 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_DP_2147651459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.DP"
        threat_id = "2147651459"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 8b 45 ?? 8b 40 ?? 03 c8 ff 15 ?? ?? ?? ?? 8d 4d ?? 51 8b 15 ?? ?? ?? ?? 52 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 4d ?? 51 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 04 8b 4d ?? 8b 49 ?? 03 c8 ff 15 ?? ?? ?? ?? 8d 55 ?? 52 a1 ?? ?? ?? ?? 50 8b 0d ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d 55 ?? 52 6a 00 ff 15 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 05 00 00 00 2b 41 ?? c1 e0 04 8b 4d ?? 8b 49 ?? 03 c8 ff 15 ?? ?? ?? ?? 8d 55 ?? 52 a1 ?? ?? ?? ?? 50 8b 0d ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 8d 55 ?? 52 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {50 8d 45 e8 50 ff 15 ?? ?? ?? ?? 8b f0 68 ?? ?? ?? ?? 56 8b 0e ff 91 ?? ?? ?? ?? 3b c7 db e2 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_P_2147652775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!P"
        threat_id = "2147652775"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e1 04 8b 45 ?? 8b 40 ?? 03 c8 e8 ?? ?? ?? ?? 8d 45 ?? 50 ff 35 ?? ?? ?? ?? ff 75 ?? e8 ?? ?? ?? ?? 8d 45 ?? 50 6a 00 e8 ?? ?? ?? ?? c7 45 ?? ?? 00 00 00 6a 00 6a 05 6a 01 6a 00 8d 45 ?? 50 6a 10 68 80 08 00 00 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {c1 e1 04 8b 45 ?? 8b 40 ?? 03 c8 e8 ?? ?? ?? ?? 8d 45 ?? 89 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 03 40 00 00 8d 95 ?? ?? ?? ?? 8b 45 ?? 6a 08 59 2b 48 ?? c1 e1 04 8b 45 ?? 8b 40 ?? 03 c8 e8 ?? ?? ?? ?? 8d 45 ?? 50 ff 35 ?? ?? ?? ?? ff 75 ?? e8 ?? ?? ?? ?? 8d 45 ?? 50 6a 00 e8}  //weight: 5, accuracy: Low
        $x_2_3 = {c1 e1 04 8b 85 ?? ?? ?? ?? 8b 40 ?? 03 c8 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 50 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 6a 00 e8}  //weight: 2, accuracy: Low
        $x_2_4 = {33 c9 2b 48 ?? c1 e1 04 8b (85 ?? ?? ?? ??|45 ??) 8b 40 ?? 03 c8 e8 ?? ?? ?? ?? 8d (85 ?? ?? ?? ??|45 ??) 50 ff (35 ?? ?? ?? ??|75 ??) ff 75 ?? e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d (85 ?? ?? ?? ??|45 ??) 50 6a 00 e8}  //weight: 2, accuracy: Low
        $x_2_5 = {c1 e1 04 8b (85 ?? ?? ?? ??|45 ??) 8b 40 ?? 03 c8 e8 ?? ?? ?? ?? 8d (85 ?? ?? ?? ??|45 ??) 50 ff 75 ?? 8d 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d (85 ?? ?? ?? ??|45 ??) 50 6a 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_Q_2147652847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!Q"
        threat_id = "2147652847"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 1c 8b 45 08 ff 30 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 03 00 00 00 8d b5 ?? ?? ?? ?? 6a 00 ff b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 50 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ff 8d 85 ?? ?? ?? ff 50 6a 00 e8}  //weight: 5, accuracy: Low
        $x_2_2 = {8b c8 8b d6 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 50 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 89 45 ?? 8d 4d ?? e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_R_2147652960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!R"
        threat_id = "2147652960"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c8 8b d6 e8 ?? ?? ?? ?? 8d 45 ?? 89 85 ?? ?? ?? ?? c7 85 ?? ?? ff ff 03 40 00 00 8d b5 ?? ?? ff ff 6a 08 ff 75 ?? e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? 8d 45 ?? 50 ff (35 ?? ?? ?? ??|75 ??) ff 75 ?? e8 ?? ?? ?? ?? 8d 45 ?? 50 6a 00 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {8b c8 8b d6 e8 ?? ?? ?? ?? 8d 45 ?? 89 85 ?? ?? ?? ?? c7 85 ?? ?? ff ff 03 40 00 00 8d b5 ?? ?? ff ff 6a 08 ff 75 ?? e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? 8d 45 ?? 50 ff 75 ?? 8d 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 45 ?? 50 6a 00 e8}  //weight: 5, accuracy: Low
        $x_20_3 = {8b c8 8b d6 e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 35 ?? ?? ?? ?? ff 75 ?? e8 ?? ?? ?? ?? 89 85 ?? ?? ff ff 8d 85 ?? ?? ff ff 50 6a 00 e8}  //weight: 20, accuracy: Low
        $x_3_4 = {66 b9 a4 00 e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ff ff 88 01}  //weight: 3, accuracy: Low
        $x_2_5 = {c3 00 8d 45 04 00 66 c7 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_S_2147653726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!S"
        threat_id = "2147653726"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {99 b9 ef 82 be 00 f7 f9 a1 03 00 8b 45}  //weight: 7, accuracy: Low
        $x_7_2 = {ff f3 00 00 00 c7 85 ?? ?? ff ff 02 00 00 00 8d [0-46] c7 85 ?? ?? ff ff a4 00 00 00}  //weight: 7, accuracy: Low
        $x_7_3 = {b9 f3 00 00 00 ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ff ff 88 02 [0-53] b9 a4 00 00 00}  //weight: 7, accuracy: Low
        $x_7_4 = {66 b9 f3 00 e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ff ff 88 01 [0-208] 66 b9 a4 00}  //weight: 7, accuracy: Low
        $x_7_5 = {66 b9 f3 00 e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ff ff 88 01}  //weight: 7, accuracy: Low
        $x_7_6 = {66 b9 a4 00 e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ff ff 88 01}  //weight: 7, accuracy: Low
        $x_7_7 = {b9 f3 00 00 00 ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ff ff 88 02}  //weight: 7, accuracy: Low
        $x_7_8 = {b9 a4 00 00 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ff ff 88 01}  //weight: 7, accuracy: Low
        $x_7_9 = {b9 f3 00 00 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ff ff 88 01}  //weight: 7, accuracy: Low
        $x_7_10 = {b9 a4 00 00 00 ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ff ff 88 02}  //weight: 7, accuracy: Low
        $x_1_11 = {50 68 43 1f 00 00 ff 35 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_12 = {50 68 40 1f 00 00 ff 35 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_13 = {43 1f 00 00 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_14 = {40 1f 00 00 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_15 = {43 1f 00 00 06 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_16 = {40 1f 00 00 06 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_17 = {40 1f c7 45 04 00 66 c7 45}  //weight: 1, accuracy: Low
        $x_1_18 = {43 1f c7 45 04 00 66 c7 45}  //weight: 1, accuracy: Low
        $x_1_19 = {29 23 c7 45 04 00 66 c7 45}  //weight: 1, accuracy: Low
        $x_1_20 = {2a 23 c7 45 04 00 66 c7 45}  //weight: 1, accuracy: Low
        $x_1_21 = {40 1f c7 45 07 00 66 c7 85}  //weight: 1, accuracy: Low
        $x_1_22 = {43 1f c7 45 07 00 66 c7 85}  //weight: 1, accuracy: Low
        $x_1_23 = {29 23 c7 45 07 00 66 c7 85}  //weight: 1, accuracy: Low
        $x_1_24 = {2a 23 c7 45 07 00 66 c7 85}  //weight: 1, accuracy: Low
        $x_7_25 = {ff c3 00 8d 06 00 66 c7 85 ?? ?? ff}  //weight: 7, accuracy: Low
        $x_7_26 = {c3 00 8d 45 04 00 66 c7 45}  //weight: 7, accuracy: Low
        $x_7_27 = {c3 00 8d 55 04 00 66 c7 45}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_T_2147653762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!T"
        threat_id = "2147653762"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e1 04 8b 45 ?? 8b 40 ?? 03 c8 e8 ?? ?? ?? ?? 8d 45 ?? 50 ff 75 ?? ff 75 ?? e8 ?? ?? ?? ?? 8d 45 ?? 50 6a 00 e8 ?? ?? ?? ?? c7 45 ?? ?? 00 00 00 (6a 00|6a 00 6a 00) e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 45 ?? ?? 00 00 00 6a 00 6a 05 6a 01 6a 00 8d 45 ?? 50 6a 10 68 80 08 00 00 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {c1 e1 04 8b 45 ?? 8b 40 ?? 03 c8 e8 ?? ?? ?? ?? 8d 45 ?? 50 ff 75 ?? ff 75 ?? e8 ?? ?? ?? ?? 8d 45 ?? 50 6a 00 e8 ?? ?? ?? ?? c7 45 ?? ?? 00 00 00 6a 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 45 ?? ?? 00 00 00 6a 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 45 ?? ?? 00 00 00 6a 00 6a 05 6a 01 6a 00 8d 45 ?? 50 6a 10 68 80 08 00 00 e8}  //weight: 5, accuracy: Low
        $x_2_3 = {c1 e1 04 8b (85 ?? ?? ?? ??|45 ??) 8b 40 ?? 03 c8 e8 ?? ?? ?? ?? 8d (85 ?? ?? ?? ??|45 ??) 50 ff 75 ?? 8d 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d (85 ?? ?? ?? ??|45 ??) 50 6a 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vobfus_U_2147656487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!U"
        threat_id = "2147656487"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 0f 80 10 00 6c 78 ff e4 f4 ff fe 5d 20 02}  //weight: 1, accuracy: High
        $x_1_2 = {00 10 6c 78 ff e4 04 74 ff f5 00 00 00 00 fc 77}  //weight: 1, accuracy: High
        $x_1_3 = {40 f5 01 00 00 00 fc 78 16 00 00 1e 6b ?? ?? 94 08 00 ?? 00 6c ?? ?? aa 6c ?? ?? 94 08 00}  //weight: 1, accuracy: Low
        $x_1_4 = {f5 00 00 00 00 f5 ff ff ff ff 04 ?? ?? fe 8e 00 00 00 00 10 00 80 08 04 ?? ?? 94 08 00 ?? ?? 94 08 00 ?? ?? 5e ?? ?? ?? ?? 71 ?? ?? 04 ?? ?? 5a 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Vobfus_V_2147658167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!V"
        threat_id = "2147658167"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c8 8b d6 e8 ?? ?? ?? ff 8d 45 ?? 50 ff 35 ?? ?? ?? 00 ff 35 ?? ?? ?? 00 e8 ?? ?? ?? ?? 8d 45 ?? 50 6a 00 e8 ?? ?? ?? ff c7 45 fc ?? ?? 00 00}  //weight: 5, accuracy: Low
        $x_2_2 = {50 6a 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 45 fc 14 00 00 00 8d 45 ?? 50 e8 ?? ?? ?? ?? 89 45 ?? c7 45 fc 15 00 00 00 6a 00 6a 02 6a 01 6a 00 8d 45 ?? 50 6a 10 68 80 08 00 00 e8 ?? ?? ?? ?? 83 c4 ?? c7 45 ?? 02 00 00 00 c7 45 ?? 02 00 00 00 8d 75 ?? 6a 00 ff 75 ?? e8 ?? ?? ?? ?? 8b c8 8b d6 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_W_2147658210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!W"
        threat_id = "2147658210"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 01 00 00 00 1b ?? 00 94 08 00 ?? ?? f5 02 00 00 80 59 ?? ff 0a ?? ?? 10 00}  //weight: 1, accuracy: Low
        $x_1_2 = {fb 12 fc 0d 6c ?? ?? 80 ?? ?? fc a0}  //weight: 1, accuracy: Low
        $x_1_3 = {e7 aa f5 00 01 00 00 c2 07 00 4a c2 6c ?? ff fc 90}  //weight: 1, accuracy: Low
        $x_1_4 = {00 56 42 2e 54 69 6d 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 56 42 2e 44 69 72 4c 69 73 74 42 6f 78 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 4e 00 6f 00 41 00 75 00 74 00 6f 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_X_2147662835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!X"
        threat_id = "2147662835"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 68 00 6f 00 77 00 53 00 75 00 70 00 65 00 72 00 48 00 69 00 64 00 64 00 65 00 6e 00 [0-16] 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e [0-16] 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 3b 00 20 00 4d 00 53 00 49 00 45 00 20 00 37 00 2e 00 30 00 3b 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 35 00 2e 00 31 00 3b 00 20 00 53 00 56 00 31 00 29 00 [0-16] 5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 37 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 53 56 31 29 [0-16] 5b 61 75 74 6f 72 75 6e 5d}  //weight: 1, accuracy: Low
        $x_1_5 = {62 00 63 00 64 00 66 00 67 00 68 00 6a 00 6b 00 6c 00 6d 00 6e 00 70 00 71 00 72 00 73 00 74 00 76 00 77 00 78 00 79 00 7a 00 [0-16] 69 00 63 00 6f 00 [0-16] 74 00 61 00 73 00 6b 00 [0-16] 70 00 72 00 6f 00 63 00}  //weight: 1, accuracy: Low
        $x_1_6 = {62 63 64 66 67 68 6a 6b 6c 6d 6e 70 71 72 73 74 76 77 78 79 7a [0-16] 69 63 6f [0-16] 74 61 73 6b [0-16] 70 72 6f 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Vobfus_Y_2147670895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!Y"
        threat_id = "2147670895"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {aa f5 00 01 00 00 c2}  //weight: 1, accuracy: High
        $x_1_2 = {f4 3c eb b3 e8 71 ?? ?? 1e ?? ?? ?? ?? 6c ?? ?? f5 ff ff ff 7f c4}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 bb c0 c0 00 ec b6 [0-8] ec f5 2f a0 bf 00 ec b6 ab}  //weight: 1, accuracy: Low
        $x_1_4 = {f5 c2 c0 c0 00 c2 [0-28] f5 2a a0 bf 00 c2}  //weight: 1, accuracy: Low
        $x_1_5 = {f5 04 80 00 00 c7 1c}  //weight: 1, accuracy: High
        $x_1_6 = {4a f5 01 00 00 00 ae f5 02 00 00 00 fe 6c}  //weight: 1, accuracy: High
        $x_1_7 = {f5 58 59 59 59}  //weight: 1, accuracy: High
        $x_1_8 = {f5 1c 00 00 00 aa 08 08 00 8f 34 00}  //weight: 1, accuracy: High
        $x_1_9 = {f5 2c 23 00 00 3e ?? ?? 23}  //weight: 1, accuracy: Low
        $x_1_10 = {f5 40 1f 00 00 3e ?? ?? 23}  //weight: 1, accuracy: Low
        $x_1_11 = {f5 43 1f 00 00 3e ?? ?? 23}  //weight: 1, accuracy: Low
        $x_1_12 = {f5 2a 23 00 00 3e ?? ?? 23}  //weight: 1, accuracy: Low
        $x_1_13 = {f5 2b 23 00 00 3e ?? ?? 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Vobfus_MV_2147671934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.MV"
        threat_id = "2147671934"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tirsinemidie mascharacterazataon Putestutive suguorumo)scopala Branchuura demidulmen Hembeldtine:" wide //weight: 1
        $x_1_2 = "Porpitu commemoreble Discipliner sodduningly polyspondylic3aftergame hypergeddess Phantom Meatless coronagraph" wide //weight: 1
        $x_1_3 = "jjomvumm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_MW_2147671935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.MW"
        threat_id = "2147671935"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "devustute attraverse2Meulless Tropicalia meccawee fastegated preprovide3Sciniph indistinctive knickur induficiunt unfooling" wide //weight: 1
        $x_1_2 = "Treungulur eseleero" wide //weight: 1
        $x_1_3 = "uujzctkr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_Z_2147678656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.gen!Z"
        threat_id = "2147678656"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8B4C240851<PATCH1>E8<PATCH2>5989016631C0C3" wide //weight: 1
        $x_1_2 = {73 00 62 00 69 00 65 00 64 00 6c 00 6c 00 0d 00 0a 00 64 00 62 00 67 00 68 00 65 00 6c 00 70 00 0d 00 0a 00 73 00 6e 00 78 00 68 00 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 57 00 69 00 6e 00 52 00 41 00 52 00 5c 00 52 00 61 00 72 00 2e 00 65 00 78 00 65 00 0d 00 0a 00 20 00 61 00 20 00 2d 00 79 00 20 00 2d 00 65 00 70 00 20 00 2d 00 49 00 42 00 43 00 4b 00}  //weight: 1, accuracy: High
        $x_1_4 = "cmd /c tasklist&&del" wide //weight: 1
        $x_1_5 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 0d 00 0a 00 2e 00 65 00 78 00 65 00 0d 00 0a 00 3a 00 2e 00 64 00 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {78 00 2e 00 6d 00 70 00 65 00 67 00 0d 00 0a 00 53 00 65 00 63 00 72 00 65 00 74 00 0d 00 0a 00 53 00 65 00 78 00 79 00 0d 00 0a 00 50 00 6f 00 72 00 6e 00}  //weight: 1, accuracy: High
        $x_1_7 = "oq2*mckxjbnof}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_Win32_Vobfus_ABD_2147708325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.ABD"
        threat_id = "2147708325"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\winlogons.exe" wide //weight: 1
        $x_1_2 = "\\SYS_Recovery.exe" wide //weight: 1
        $x_1_3 = "\\sysData.txt" wide //weight: 1
        $x_1_4 = "_kabe" wide //weight: 1
        $x_1_5 = {53 00 74 00 61 00 72 00 74 00 75 00 70 00 [0-10] 53 00 70 00 65 00 63 00 69 00 61 00 6c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 [0-10] 25 00 74 00 65 00 6d 00 70 00 25 00 [0-10] 45 00 78 00 70 00 61 00 6e 00 64 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 73 00}  //weight: 1, accuracy: Low
        $x_1_6 = "taskkill /f /im msconfig.exe" wide //weight: 1
        $x_1_7 = "taskkill /f /im regedit.exe" wide //weight: 1
        $x_1_8 = "taskkill /f /im avira_antivir_personal.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Vobfus_AI_2147826897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.AI!MTB"
        threat_id = "2147826897"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegFlushKey" ascii //weight: 1
        $x_1_2 = "MaskEdBox1" ascii //weight: 1
        $x_1_3 = "CallWindowProcW" ascii //weight: 1
        $x_1_4 = "HappyFeet.dll" ascii //weight: 1
        $x_1_5 = "www.Arvinder.co.uk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_AP_2147830407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.AP!MTB"
        threat_id = "2147830407"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 00 ca 11 43 00 30 12 43 00 80 12 43 00 92 12 43 00 e2}  //weight: 2, accuracy: High
        $x_2_2 = {43 00 ee 2f 43 00 38 30 43 00 82 30 43 00 cc 30 43}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_BD_2147835263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.BD!MTB"
        threat_id = "2147835263"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {be 40 00 17 bf 40 00 38 bf 40 00 59 bf 40 00 8b bf 40 00 8d bf 40 00 8d bf 40 00 ae bf 40 00 cf bf 40 00 d4 bf 40 00 f5 bf 40 00 16 c0 40 00 37}  //weight: 2, accuracy: High
        $x_2_2 = {30 41 00 c5 30 41 00 e6 30 41 00 02 31 41 00 23 31 41 00 44 31 41 00 65 31 41 00 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_HNS_2147905903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.HNS!MTB"
        threat_id = "2147905903"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ea 77 a4 72 41 98 a4 72 07 05 a2 72 86 93 a3 72 f9 09 a3 72 ee 6a a4 72 37 05 a2 72 8d 72 a4 72 fd a0 94 72 31 68 a4 72 44 c2 a0 72 9b 6a a2 72 29 19 a2 72 62 72 a4 72 fa 56 a2 72 88 be a0 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vobfus_G_2147924426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vobfus.G!MTB"
        threat_id = "2147924426"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 00 32 08 00 28 ff 24 ff 20 ff 1c ff 1a e8 fe 00}  //weight: 10, accuracy: High
        $x_1_2 = "Virus asli buatan Ambon Manise-Maluku" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

