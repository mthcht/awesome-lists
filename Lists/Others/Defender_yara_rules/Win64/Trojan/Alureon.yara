rule Trojan_Win64_Alureon_A_154091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!A"
        threat_id = "154091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 40 10 74 c6 40 11 64 41 8a da 45 8a ea 45 8a e2 c6 40 12 6c}  //weight: 1, accuracy: High
        $x_1_2 = {3c 0d 75 06 c6 03 00 48 ff c3 80 3b 0a}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 47 06 48 83 c6 28 ff c5 4c 03 d9 3b e8 72 ?? 48 63 41 3c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Alureon_B_154092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!B"
        threat_id = "154092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 43 46 00 00 66 39 03 74 ?? b8 43 44 00 00 66 39 03 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 b8 14 00 00 00 80 f7 ff ff 8b 00 48 89 0d ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 89 05 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {49 8b 40 18 48 8d 35 ?? ?? ?? ?? 48 8b f8 b9 00 02 00 00 f3 a4 48 8b 03 48 85 c0 74 ?? 4c 8b 43 08}  //weight: 1, accuracy: Low
        $x_1_4 = "IN MINT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Alureon_C_161296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!C"
        threat_id = "161296"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 00 02 00 00 b2 28 44 89 64 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b8 43 44 00 00 66 39 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Alureon_D_161297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!D"
        threat_id = "161297"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 0a 48 83 c2 01 44 3b c0 72 ed 80 3b 4d 75 ?? 80 7b 01 5a}  //weight: 2, accuracy: Low
        $x_1_2 = {0f b7 69 3c 48 8b f1 66 81 7c 29 18 0b 01 74 07 33 c0 e9 ?? ?? ?? ?? 8b 54 29 50 48 8b 4c 29 30}  //weight: 1, accuracy: Low
        $x_1_3 = {44 6f 77 6e 6c 6f 61 64 54 6f 46 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Alureon_C_164685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.C"
        threat_id = "164685"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6c 73 61 73 68 2e 78 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 63 6d 64 36 34 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 b8 66 69 72 65 66 6f 78 00 48 89 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Alureon_E_165680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!E"
        threat_id = "165680"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 53 46 00 00 48 03 c2 41 b9 00 02 00 00 b1 2a 48 c1 f8 09}  //weight: 1, accuracy: High
        $x_1_2 = {48 b8 14 00 00 00 80 f7 ff ff 8b 00 89 05 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 44}  //weight: 1, accuracy: Low
        $x_1_3 = "IN MINT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Alureon_F_165681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!F"
        threat_id = "165681"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 00 02 00 00 b2 28 44 89 64 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b8 53 44 00 00 66 39 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Alureon_D_167758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.D"
        threat_id = "167758"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 20 00 75 00 61 00 63 00 36 00 34 00 6f 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 b9 00 30 00 00 41 b8 06 01 00 00 c7 44 24 ?? 04 00 00 00 ff 15 ?? ?? ?? ?? 48 8b f0 48 3b c3 0f 84 ?? ?? 00 00 48 83 c9 ff 33 c0 48 8b fd 66 f2 af 48 8d 44 24 ?? 4c 8b c5 48 f7 d1 48 8b d6 48 89 44 24 ?? 4c 8d 0c 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Alureon_E_167762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.E"
        threat_id = "167762"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 48 8b 04 25 88 01 00 00 48 8b d3 48 89 83 ?? 00 00 00 48 8b 83 ?? 00 00 00 48 89 48 ?? 48 83 e8 48 49 8b cc 4c 89 60 ?? c6 00 0f fe 4b ?? 48 89 83 ?? 00 00 00 41 ff d5 3d 03 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {80 3f 0e 0f 85 ?? ?? 00 00 81 7f 18 30 d0 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Alureon_G_168178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!G"
        threat_id = "168178"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 81 e1 00 e0 ff ff 76 1f 66 90 66 81 39 4d 5a 75 0d 48 63 41 3c 81 3c 08 50 45 00 00 74 09 48 81 e9 00 10 00 00 75 e3}  //weight: 1, accuracy: High
        $x_1_2 = {83 7e 04 ff 74 71 8b 7e 10 8b 06 89 6e 08 49 03 fc 85 c0 c7 46 04 37 13 c3 cd}  //weight: 1, accuracy: High
        $x_1_3 = {41 8b 49 0c 41 8b 51 08 41 81 61 0c 0f 08 00 f0 48 8b c1 4c 8b c2 48 25 00 00 00 f8 41 81 e0 ff ff 7f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Alureon_H_168179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!H"
        threat_id = "168179"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 69 6e 6a 65 63 74 73 5f 62 65 67 69 6e 5f 36 34 5d 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 41 52 4b 45 52 5f 41 46 46 49 44 00 00 00 00 4d 41 52 4b 45 52 5f 53 55 42 49 44 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 bc 3f 00 00 c0 41 3b c4 75 63 48 8b 53 08 48 8b cf e8}  //weight: 1, accuracy: High
        $x_1_4 = {66 81 3a 4d 5a 75 0d 48 63 42 3c 81 3c 10 50 45 00 00 74 09 48 81 ea 00 10 00 00 75 e3 48 8d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Alureon_I_168180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!I"
        threat_id = "168180"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 3b 42 4b 46 53 74 07 b8 00 a0 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {41 8b 01 25 ff ff ff 03 8d 0c 83 c1 f9 02 41 33 09 81 e1 ff ff ff 03 41 33 09 41 89 09}  //weight: 1, accuracy: High
        $x_1_3 = {b8 0d 00 00 c0 41 23 c6 41 3b c6 0f 84 e3 00 00 00 48 8b 45 b8 33 c9 8b 50 14 c1 e2 09 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {ff ca 41 0b d5 ff c2 0f b6 da 41 fe c0 8a 04 1c 41 80 e0 03 88 07 48 ff c7 49 ff cb 40 88 34 1c 75 c8 45 85 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Alureon_J_169874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!J"
        threat_id = "169874"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 70 68 64 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_2 = "PurpleHaze" ascii //weight: 1
        $x_1_3 = {b8 53 46 00 00 66 39 03 74 0a b8 53 44 00 00 66 39 03 75}  //weight: 1, accuracy: High
        $x_1_4 = {b9 10 27 00 00 ff 15 ?? ?? ?? ?? e9 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 45 33 c0 ff 15 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Alureon_K_171948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!K"
        threat_id = "171948"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 74 24 08 44 8d 48 04 ba 00 00 10 00 33 c9 41 b8 00 30 00 00 bf 77 07 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 40 16 44 8d 63 01 c1 e8 0d 41 23 c4 0f 84 ?? ?? ?? ?? ff cf}  //weight: 1, accuracy: Low
        $x_1_3 = "restart64" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Alureon_L_176339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!L"
        threat_id = "176339"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca b8 55 aa 00 00 d1 e9 03 ca b2 80 c1 e9 05 6b c9 3f 2b d9 b9 f7 00 00 00 f3 a4 fe c3 b1 2a}  //weight: 1, accuracy: High
        $x_1_2 = {b8 53 46 00 00 66 39 03 74 0a b8 53 44 00 00 66 39 03 75}  //weight: 1, accuracy: High
        $x_1_3 = {48 83 c2 28 8b c8 41 ff c0 f3 a4 8b 7a 04 48 8b 4d ?? 41 0f b7 44 24 06 48 03 f9 44 3b c0 72 cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Alureon_M_197326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!M"
        threat_id = "197326"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 43 04 66 ff 43 06 41 bd 64 86 00 00 66 41 3b c5 75 03 01 7b 50}  //weight: 1, accuracy: High
        $x_1_2 = {74 22 44 8b 43 54 4c 8b c8 33 d2 33 c9 4c 03 c0 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 53 18 48 8b cf ff 13}  //weight: 1, accuracy: High
        $x_1_3 = {42 0f b6 04 11 41 32 44 1b ff 49 ff c9 88 43 ff 75 a3 48 83 c4 20 5b c3}  //weight: 1, accuracy: High
        $x_1_4 = {73 64 72 6f 70 70 65 72 36 34 2e 65 78 65 00 44 6f 77 6e 6c 6f 61 64 52 75 6e 45 78 65 49 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Alureon_N_197449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.gen!N"
        threat_id = "197449"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 ff 15 ?? ?? ?? ?? 33 d2 48 8d 4c 24 78 c7 44 24 70 68 00 00 00 44 8d 42 60 e8 49 01 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 00 5c 5c 2e 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 77 6f 77 36 34 5c 77 69 6e 72 73 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {00 57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Alureon_K_198845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.K"
        threat_id = "198845"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[kit64_hash_end]" ascii //weight: 1
        $x_1_2 = "[cmd_dll64_hash_end]" ascii //weight: 1
        $x_1_3 = {8d 42 51 48 83 c2 01 30 44 0a ff 48 81 fa 00 01 00 00 72 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Alureon_L_200017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.L"
        threat_id = "200017"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 49 6e 6a 65 63 74 36 34 53 74 61 72 74 00 [0-16] 49 6e 6a 65 63 74 36 34 45 6e 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 40 04 3d 64 86 00 00 75 0e 48 8b 44 24 ?? 48 8b 40 30 48 89 44 24 ?? 48 8b 44 24 ?? 0f b7 40 04 3d 4c 01 00 00 75 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Alureon_M_200119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alureon.M"
        threat_id = "200119"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 44 24 28 ba 01 00 00 00 48 03 c1 ff d0 85 c0 75 0f 48 8b 4f 18 33 d2 41 b8 00 80 00 00 41 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {41 81 7f 18 3c 3c 22 00 75 23 44 88 25 ?? ?? ?? ?? eb 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

