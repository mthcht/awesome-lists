rule TrojanDownloader_Win32_Nymaim_A_2147678986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nymaim.A"
        threat_id = "2147678986"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 ea 11 11 11 11 (8d 9d 00 fd|e9 8d 9d 00 fd)}  //weight: 10, accuracy: Low
        $x_1_2 = {c7 03 66 69 6c 65 (c7 43 04 6e 61|e9 c7 43 04 6e 61) [0-16] (c6 43|e9 c6 43)}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 03 26 64 61 74 (66 c7 43 04|e9 66 c7 43 04)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Nymaim_B_2147680306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nymaim.B"
        threat_id = "2147680306"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 e6 11 11 11 11 [0-32] 8d 9d fc fc ff ff}  //weight: 10, accuracy: Low
        $x_1_2 = {c7 03 66 69 6c 65 [0-32] c7 43 04 6e 61 6d 65 [0-32] c6 43 08 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 03 26 64 61 74 [0-32] 66 c7 43 04 61 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 06 46 08 c0 0f 84 86 f3 ff ff 0d 20 20 20 20 3d 73 6f 63 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Nymaim_C_2147684634_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nymaim.C"
        threat_id = "2147684634"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 5b 5e 5f 8b 4d 0c 83 c1 04 c1 e1 02 8b 55 10 c9 01 cc ff e2}  //weight: 1, accuracy: High
        $x_1_2 = {88 07 47 46 08 c0 75 e1 89 f8 5f 5e 59 c9 c2 08 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 7c 24 04 ?? 0f 85 ?? ?? ff ff 89 4c 24 04 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {89 c2 58 89 f9 81 e9 ?? ?? ?? ?? 51 c1 e9 02 83 f9 00 74 05 01 d3 49 75 fb 59 83 e1 03 c1 e1 03 d3 cb 8a 07 30 d8 59 5f 5b 5a c9 c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Nymaim_G_2147694569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nymaim.G"
        threat_id = "2147694569"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc d1 f8 8b 4d 08 0f be 04 01 0f b6 4d 0c 33 c1 8b 4d f8 88 01}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 01 68 ?? ?? ?? ?? 58 83 ec fd 50 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Nymaim_G_2147694569_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nymaim.G"
        threat_id = "2147694569"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 88 45 ?? 8b 45 ?? 25 ff 00 00 00 88 45 ?? ff 75 ?? ff 75 ?? e8 ?? ?? ff ff 59 59 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 08 c3 0c 00 8d 15 ?? ?? ?? ?? 52 68}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 59 59 68 ?? ?? ?? ?? e8 ?? ff ff ff 0f 00 ff ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Nymaim_H_2147708367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nymaim.H"
        threat_id = "2147708367"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 f3 33 d2 8b c6 f7 f1 a3 ?? ?? ?? ?? 32 c0 eb 29 8b 3d 00 0f b6 f3 ff 15 ?? ?? ?? ?? 0f b6 4d ff 8d 8c 31 31 ff ff ff 33 c1 2b f8 8a c3 32 45 ff 89 3d 00 8b 4d f8 8b fb 88 01 c1 ef 10}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 08 c3 0c 00 8d 15 ?? ?? ?? ?? 52 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Nymaim_I_2147708375_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nymaim.I"
        threat_id = "2147708375"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {ff 75 08 c3 0c 00 8d 15 ?? ?? ?? ?? 52 68}  //weight: 8, accuracy: Low
        $x_1_2 = {33 ff 8d b4 7d ?? ff ff ff 0f b7 ?? [0-1] e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b c7 99 6a 19 59 f7 f9 8d 42 61 66 89 06 0f b7 c0 50 e8 ?? ?? ?? ?? [0-4] a3 04 83 ff 40 72}  //weight: 1, accuracy: Low
        $x_1_3 = {33 f6 8d 8c 75 ?? ff ff ff 0f b7 ?? [0-1] e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? [0-3] 8b c6 99 6a 19 5f f7 ff 8d 42 61 66 89 01 0f b7 [0-2] e8 ?? ?? ?? ?? [0-3] 46 a3 04 83 fe 40 72}  //weight: 1, accuracy: Low
        $x_1_4 = {33 f6 8d 4c 35 ?? 0f be 01 [0-1] e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b c6 99 6a 19 5f f7 ff 80 c2 61 0f be c2 50 88 11 e8 ?? ?? ?? ?? 46 59 [0-1] a3 03 83 fe 40 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Nymaim_L_2147722506_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nymaim.L!bit"
        threat_id = "2147722506"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 35 00 00 00 51 b9 0b 00 00 00 01 0c 24 [0-32] bf 00 30 00 00 57 [0-32] 68 ?? ?? ?? ?? 6a 00 [0-32] ff 15 [0-32] 50 8f 05}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 03 06 60 00 83 c6 04 ab 81 fe ?? ?? ?? ?? ?? ?? e8 09 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Nymaim_K_2147723763_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nymaim.K"
        threat_id = "2147723763"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 d3 8a 16 30 1e 46 01 fb c1 c3 08 49 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {32 06 46 88 07 8b 5d f4 8b 4d f8 89 ca 83 e1 03 c1 e1 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Nymaim_N_2147733529_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nymaim.N!bit"
        threat_id = "2147733529"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 33 80 3d ?? ?? ?? 00 73 0f 84 a3 f3 ff ff 89 d1 c1 ea 19 c1 e1 07 01 ca 31 c2 43 83 3d ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 4d f4 e8 ?? ?? ?? 00 32 06 46 88 07 47 ff 4d 10 75 f0}  //weight: 1, accuracy: Low
        $x_1_3 = {68 a5 cc e9 65 e8 ?? ?? ?? ff 8b 4c 24 10 66 39 04 71 74 19 68 a7 cc e9 65 e8 ?? ?? ?? ff 8b 4c 24 10 66 39 04 71}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

