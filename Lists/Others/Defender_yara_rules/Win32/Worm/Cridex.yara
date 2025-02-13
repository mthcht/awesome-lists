rule Worm_Win32_Cridex_A_2147648284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cridex.A"
        threat_id = "2147648284"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 65 6c 6c 5c [0-8] 5c 63 6f 6d 6d 61 6e 64 3d 25 53}  //weight: 1, accuracy: Low
        $x_1_2 = {68 01 00 00 80 e8 ?? ?? ?? ?? 83 c4 24 85 c0 75 c0 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e2 10 0b d1 89 15 ?? ?? ?? ?? 0f b7 94 24 ?? ?? 00 00 c1 e2 10 0b d0 89 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 d2 b9 e8 03 00 00 f7 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Cridex_B_2147649733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cridex.B"
        threat_id = "2147649733"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 65 6c 6c 5c [0-8] 5c 63 6f 6d 6d 61 6e 64 3d 25 53}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 33 d2 f7 f3 0f b7 ca 66 83 f9 0a 72 05 83 c1 37 eb 03 83 c1 30 83 ee 01 66 89 4c 77 02 8b c8 79 dd}  //weight: 1, accuracy: High
        $x_1_3 = {8b 50 fc 8b 54 ca 04 83 c1 01 89 3a 3b 08 72 f0 89 78 f8 83 c0 10 39 38 75}  //weight: 1, accuracy: High
        $x_1_4 = {0f b7 57 38 8b 44 24 10 d1 ea 8d 54 0a 10 3b d0 72 ?? 03 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c1 02 eb 0f 66 83 39 5c 74 09 66 c7 40 02 5c 00 83 c0 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Cridex_C_2147654323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cridex.C"
        threat_id = "2147654323"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 81 ec 2c 04 00 00 56 57 53 68 00 04 00 00 8d 85 d4 fb ff ff 50 ff 15 ?? ?? ?? 00 0f b6 85 d4 fb ff ff 85 c0 0f 84 ?? ?? ?? ?? 8d 85 d4 fb ff ff 50 68 00 04 00 00 ff 15 ?? ?? ?? 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f8 89 45 d4 ff 55 d4 5b 5f 5e 89 ec 5d c2 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Cridex_E_2147657563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cridex.E"
        threat_id = "2147657563"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 4d 00 53 00 25 00 30 00 38 00 58 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 58 00 4d 00 42 00 25 00 30 00 38 00 58 00 00 00}  //weight: 1, accuracy: High
        $x_2_3 = {8b 40 0c 8b 70 0c 85 f6 74 ?? 33 ff eb 83 c7 01 66 83 3c 7d ?? ?? ?? ?? 00 75 f2 83 7e 18 00 74 ?? 0f b7 (46|4e) 2c 8b 56 30 d1 (e8|e9)}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Cridex_L_2147682817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cridex.L"
        threat_id = "2147682817"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 4b 00 42 00 25 00 30 00 38 00 75 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d 0c 03 cb 51 ff 54 24 ?? 8b d0 85 d2 89 54 24 ?? 74 ?? 8b 75 00 8b 7d 10 8b 04 1e 03 f3 03 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Cridex_G_2147747815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cridex.G!MTB"
        threat_id = "2147747815"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 c6 4d 2a c1 04 4d 00 05 ?? ?? ?? ?? 8b 44 24 ?? 81 c7 ?? ?? ?? ?? 89 38 0f b7 c6 8d 84 41 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 77 ?? 8b 54 24 ?? 89 15 ?? ?? ?? ?? 8d 94 00 ?? ?? ?? ?? 66 01 15 ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 83 44 24 10 ?? 8b d8 6b db ?? 66 0f b6 f2 66 2b f3 81 7c 24 10 ?? ?? ?? ?? 66 89 35 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 c5 49 0f af c8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 66 89 2d ?? ?? ?? ?? 75 ?? 8b 3d ?? ?? ?? ?? c1 e7 03 2b 3d ?? ?? ?? ?? 2b 3d ?? ?? ?? ?? 66 89 3d ?? ?? ?? ?? 83 44 24 10 04 81 7c 24 10 ?? ?? ?? ?? 0f 82 08 00 81 c3 ?? ?? ?? ?? 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

