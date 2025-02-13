rule Trojan_Win32_Totbrick_A_2147717914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Totbrick.A"
        threat_id = "2147717914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Totbrick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 00 44 00 52 00 5f 00 58 00 36 00 34 00 42 00 4f 00 54 00 0d 00 49 00 44 00 52 00 5f 00 58 00 36 00 34 00 4c 00 4f 00 41 00 44 00 45 00 52 00 0a 00 49 00 44 00 52 00 5f 00 58 00 38 00 36 00 42 00 4f 00 54 00}  //weight: 2, accuracy: High
        $x_4_2 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 54 00 72 00 69 00 63 00 6b 00 4c 00 6f 00 61 00 64 00 65 00 72 00}  //weight: 4, accuracy: High
        $x_4_3 = {63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 63 00 6f 00 6e 00 66 00 00 00 43 00 4f 00 4e 00 46 00 49 00 47 00 00 00 00 00 67 00 72 00 6f 00 75 00 70 00 5f 00 74 00 61 00 67 00}  //weight: 4, accuracy: High
        $x_1_4 = "/plain/clientip" wide //weight: 1
        $x_1_5 = {47 00 45 00 54 00 00 00 2f 00 25 00 73 00 2f 00 25 00 73 00 2f 00 30 00 2f 00 25 00 73 00 2f 00 25 00 73 00 2f 00 25 00 73 00 2f 00 25 00 73 00 2f 00 25 00 73 00 2f 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Totbrick_C_2147719039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Totbrick.C"
        threat_id = "2147719039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Totbrick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 3e 2a 75 03 46 8b fe 8a 13 3a 16 74 04 8b f7 eb}  //weight: 1, accuracy: High
        $x_1_2 = {52 50 53 66 c7 45 e4 58 68 66 c7 45 ea 50 e9}  //weight: 1, accuracy: High
        $x_1_3 = {83 c0 41 66 89 04 53 8b 45 fc 66 83 3c 43 46 76 0c b9 e9 ff 00 00 66 01 0c 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Totbrick_D_2147719655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Totbrick.D"
        threat_id = "2147719655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Totbrick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 83 f9 19 77 03 83 c0 20 83 c6 02 c1 c2 07 0f b7 c0 47 33 d0 0f b7 06 66 85 c0 75 d5}  //weight: 1, accuracy: High
        $x_1_2 = {46 80 3e 23 75 21 8d 46 01 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Totbrick_2147721993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Totbrick"
        threat_id = "2147721993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Totbrick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d4 b8 04 0b 40 00 41 89 15 ?? ?? 44 00 03 c1 ff d0 4a 4a 8d 0d ?? ?? 44 00 51 4a 4a e8 ?? ?? fd ff 8b f1 48}  //weight: 2, accuracy: Low
        $x_1_2 = {89 54 24 08 b8 ?? 00 00 00 89 44 24 04 ba 14 00 00 00 89 54 24 0c 51 e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Totbrick_H_2147725005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Totbrick.H"
        threat_id = "2147725005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Totbrick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 06 5a 49 50 41}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 06 0f 85 ?? ?? 00 00 81 7d ?? 6d 63 63 6f 0f 85 ?? ?? 00 00 b9 6e 66 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {76 65 72 00 0f 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "gtagu" ascii //weight: 1
        $x_1_5 = {73 65 72 76 75 ?? 66 83 7d ?? 73}  //weight: 1, accuracy: Low
        $x_1_6 = {61 75 74 6f 75 ?? 81 7d ?? 72 75 6e 00}  //weight: 1, accuracy: Low
        $x_2_7 = {eb 12 3c c0 75 05 80 fc a8 eb 07 3c a9 75 07 80 fc fe 75 02}  //weight: 2, accuracy: High
        $x_1_8 = {39 51 04 75 2c 8b 41 18 8b 40 04 3c 0a 74 20}  //weight: 1, accuracy: High
        $x_1_9 = {10 66 00 00 c7 45 ?? 20 00 00 00 8d 4b 08 8d 7d ?? f3 a5 8d 4d fc}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 01 3d 73 00 54 00 75 12 81 79 04 61 00 72 00}  //weight: 1, accuracy: High
        $x_1_11 = {3d 73 00 74 00 75 10 81 79 04 41 00 72 00}  //weight: 1, accuracy: High
        $x_1_12 = {32 d1 8b 4d f8 c0 e0 06 02 45 ff 88 55 09 66 8b 55 08 66 89 11 88 41 02}  //weight: 1, accuracy: High
        $x_2_13 = {8b f0 81 fe ?? ?? 00 00 0f 84 ?? ?? 00 00 81 fe ?? ?? 00 00 74 ?? 81 fe ?? ?? 00 00 74 ?? 68 40 9c 00 00 ff 15 ?? ?? ?? ?? eb}  //weight: 2, accuracy: Low
        $x_2_14 = {58 68 66 c7 45 ?? 50 e9 89 55 ?? e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_15 = {75 16 68 30 75 00 00 ff 15 ?? ?? ?? ?? 47 83 ff 05 7c ca}  //weight: 1, accuracy: Low
        $x_3_16 = {74 33 8b 4d 10 8b 55 0c 57 8d 45 fc 50 a1 ?? ?? ?? ?? 51 8b 88 ec 00 00 00 52 56 ff d1}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Totbrick_H_2147726589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Totbrick.H!!Totbrick.gen!A"
        threat_id = "2147726589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Totbrick"
        severity = "Critical"
        info = "Totbrick: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 06 5a 49 50 41}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 06 0f 85 ?? ?? 00 00 81 7d ?? 6d 63 63 6f 0f 85 ?? ?? 00 00 b9 6e 66 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {76 65 72 00 0f 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "gtagu" ascii //weight: 1
        $x_1_5 = {73 65 72 76 75 ?? 66 83 7d ?? 73}  //weight: 1, accuracy: Low
        $x_1_6 = {61 75 74 6f 75 ?? 81 7d ?? 72 75 6e 00}  //weight: 1, accuracy: Low
        $x_2_7 = {eb 12 3c c0 75 05 80 fc a8 eb 07 3c a9 75 07 80 fc fe 75 02}  //weight: 2, accuracy: High
        $x_1_8 = {39 51 04 75 2c 8b 41 18 8b 40 04 3c 0a 74 20}  //weight: 1, accuracy: High
        $x_1_9 = {10 66 00 00 c7 45 ?? 20 00 00 00 8d 4b 08 8d 7d ?? f3 a5 8d 4d fc}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 01 3d 73 00 54 00 75 12 81 79 04 61 00 72 00}  //weight: 1, accuracy: High
        $x_1_11 = {3d 73 00 74 00 75 10 81 79 04 41 00 72 00}  //weight: 1, accuracy: High
        $x_1_12 = {32 d1 8b 4d f8 c0 e0 06 02 45 ff 88 55 09 66 8b 55 08 66 89 11 88 41 02}  //weight: 1, accuracy: High
        $x_2_13 = {8b f0 81 fe ?? ?? 00 00 0f 84 ?? ?? 00 00 81 fe ?? ?? 00 00 74 ?? 81 fe ?? ?? 00 00 74 ?? 68 40 9c 00 00 ff 15 ?? ?? ?? ?? eb}  //weight: 2, accuracy: Low
        $x_2_14 = {58 68 66 c7 45 ?? 50 e9 89 55 ?? e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_15 = {75 16 68 30 75 00 00 ff 15 ?? ?? ?? ?? 47 83 ff 05 7c ca}  //weight: 1, accuracy: Low
        $x_3_16 = {74 33 8b 4d 10 8b 55 0c 57 8d 45 fc 50 a1 ?? ?? ?? ?? 51 8b 88 ec 00 00 00 52 56 ff d1}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Totbrick_2147741162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Totbrick!MTB"
        threat_id = "2147741162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Totbrick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 2b c3 83 c0 03 a3 ?? ?? ?? ?? bd 03 00 00 00 0f b7 05 ?? ?? ?? ?? 89 44 24 18 03 c1 03 fb 81 ff ?? ?? ?? ?? 8d 6c 28 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 2b c1 83 c0 03 8b d0 0f af d3 69 d2 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 89 7d 00 39 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Totbrick_2147741162_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Totbrick!MTB"
        threat_id = "2147741162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Totbrick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ee 08 8b da 8b ce d3 fb 47 85 f6 88 5c 07 ff 75 ?? 8b 4c 24 ?? 83 c5 04 49 89 4c 24 ?? 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8b c1 bd ?? 00 00 00 f7 f5 8a 04 1a 30 04 31 41 3b cf 75}  //weight: 1, accuracy: Low
        $x_1_3 = {33 d2 8b c1 bf ?? 00 00 00 f7 f7 8a ?? 31 8a ?? ?? ?? ?? ?? 32 ?? 88 ?? 31 41 81 f9 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_4 = {33 d2 8b c1 f7 f3 0f b6 04 2a 8b 54 8c 10 03 c7 03 c2 8b f8 81 e7 ?? ?? ?? ?? 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Totbrick_I_2147742733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Totbrick.I!!Totbrick.gen!B"
        threat_id = "2147742733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Totbrick"
        severity = "Critical"
        info = "Totbrick: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 2b 83 c3 04 33 2f 83 c7 04 89 29 83 c1 04 3b de 0f 43 da 81 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 04 00 00 00 50 50 50 50 50 50 50 50 6a 02 68 40 10 00 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8a e2 c0 e0 02 c0 e2 04 c0 ec 04 80 e4 03 0a e0 8a 44 ?? ?? 88 64 ?? ?? 8a f0 c0 e0 06 02 44 ?? ?? c0 ee 02 80 e6 0f 0a f2 88 74 ?? ?? 88 44 ?? ?? 88 26}  //weight: 1, accuracy: Low
        $x_1_4 = {a3 3c 9a 87 01 b9 90 5f 01 00 68 c0 27 09 00 68 20 bf 02 00 51 51 50 ff 15 d8 b2 87 01 68 00 08 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {8d 4c 24 1c ba 20 00 00 00 c7 41 f4 08 02 00 00 c7 41 f8 10 66 00 00 89 51 fc}  //weight: 1, accuracy: High
        $x_1_6 = {0f be 39 41 03 fa 8b df c1 e3 0a 03 df 8b d3 c1 ea 06 33 d3 48 75 ?? 8b 3c 24 8d 04 d2 eb 02 33 c0 8b c8 c1 e9 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Totbrick_AD_2147742847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Totbrick.AD!MTB"
        threat_id = "2147742847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Totbrick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 2b ce 01 4c 24 ?? 8d 4c 3b ?? 66 89 0d ?? ?? ?? ?? 8b 4c 24 14 8b 09 89 0d ?? ?? ?? ?? 0f b7 4c 24 10 bd ?? ?? ?? ?? 8d bc 0f ?? ?? ?? ?? 3b f5 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 14 8b 15 ?? ?? ?? ?? 89 10 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 3d ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

