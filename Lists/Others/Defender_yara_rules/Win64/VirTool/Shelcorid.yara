rule VirTool_Win64_Shelcorid_A_2147849675_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelcorid.A"
        threat_id = "2147849675"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelcorid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 59 49 89 c8 48 81 ?? ?? ?? ?? 00 ba ?? ?? ?? ?? 49 81 ?? ?? ?? ?? 00 41 b9 04 00 00 00 56 48 89 e6 48 83 e4 f0 48 83 ec 30 c7 44 24 ?? ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 00 65 00 48 8b f1 4c 89 7d f8 b9 13 9c bf bd}  //weight: 1, accuracy: High
        $x_1_3 = {52 74 6c 41 c7 45 ?? 64 64 46 75 c7 45 ?? 6e 63 74 69 c7 45 ?? 6f 6e 54 61 66 c7 ?? ?? 62 6c e8 ?? ?? ?? ?? b9 b5 41 d9 5e 48 8b d8 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b c4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 ec 10 65 ?? ?? ?? ?? ?? ?? ?? ?? 8b e9 45 33 f6 48 8b 50 18 4c 8b 4a 10 4d 8b 41 30 4d 85 c0 0f 84 ?? ?? ?? ?? 41 0f 10 41 58 49 63 40 3c 41 8b d6 4d 8b 09 f3 0f 7f 04 24 46 8b 9c 00 88 00 00 00 45 85 db ?? ?? 48 8b 04 24 48 c1 e8 10 66 44 3b f0 ?? ?? 48 8b 4c 24 08 44 0f b7 d0 0f be 01 c1 ca 0d 80 39 61 ?? ?? 83 c2 e0 03 d0 48 ff c1 49 83 ea 01 ?? ?? 4f 8d 14 18 45 8b de 41 8b 7a 20 49 03 f8 45 39 72 18 ?? ?? 8b 37 41 8b de 49 03 f0 48 8d 7f 04 0f be 0e 48 ff c6 c1 cb 0d 03 d9 84 c9 ?? ?? 8d 04 13 3b c5 ?? ?? 41 ff c3 45 3b 5a 18 ?? ?? e9 ?? ?? ?? ?? 41 8b 42 24 43 8d 0c 1b 49 03 c0 0f b7 14 01 41 8b 4a 1c 49 03 c8 8b 04 91 49 03 c0 ?? ?? 33 c0 48 8b 5c 24 20 48 8b 6c 24 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Shelcorid_A_2147849678_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelcorid.A!!Shelcorid.gen!A"
        threat_id = "2147849678"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelcorid"
        severity = "Critical"
        info = "Shelcorid: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 59 49 89 c8 48 81 ?? ?? ?? ?? 00 ba ?? ?? ?? ?? 49 81 ?? ?? ?? ?? 00 41 b9 04 00 00 00 56 48 89 e6 48 83 e4 f0 48 83 ec 30 c7 44 24 ?? ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 00 65 00 48 8b f1 4c 89 7d f8 b9 13 9c bf bd}  //weight: 1, accuracy: High
        $x_1_3 = {52 74 6c 41 c7 45 ?? 64 64 46 75 c7 45 ?? 6e 63 74 69 c7 45 ?? 6f 6e 54 61 66 c7 ?? ?? 62 6c e8 ?? ?? ?? ?? b9 b5 41 d9 5e 48 8b d8 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b c4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 ec 10 65 ?? ?? ?? ?? ?? ?? ?? ?? 8b e9 45 33 f6 48 8b 50 18 4c 8b 4a 10 4d 8b 41 30 4d 85 c0 0f 84 ?? ?? ?? ?? 41 0f 10 41 58 49 63 40 3c 41 8b d6 4d 8b 09 f3 0f 7f 04 24 46 8b 9c 00 88 00 00 00 45 85 db ?? ?? 48 8b 04 24 48 c1 e8 10 66 44 3b f0 ?? ?? 48 8b 4c 24 08 44 0f b7 d0 0f be 01 c1 ca 0d 80 39 61 ?? ?? 83 c2 e0 03 d0 48 ff c1 49 83 ea 01 ?? ?? 4f 8d 14 18 45 8b de 41 8b 7a 20 49 03 f8 45 39 72 18 ?? ?? 8b 37 41 8b de 49 03 f0 48 8d 7f 04 0f be 0e 48 ff c6 c1 cb 0d 03 d9 84 c9 ?? ?? 8d 04 13 3b c5 ?? ?? 41 ff c3 45 3b 5a 18 ?? ?? e9 ?? ?? ?? ?? 41 8b 42 24 43 8d 0c 1b 49 03 c0 0f b7 14 01 41 8b 4a 1c 49 03 c8 8b 04 91 49 03 c0 ?? ?? 33 c0 48 8b 5c 24 20 48 8b 6c 24 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Shelcorid_B_2147914728_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelcorid.B"
        threat_id = "2147914728"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelcorid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 00 65 00 48 8b f1 4c 89 7d ?? b9 13 9c bf bd}  //weight: 1, accuracy: Low
        $x_1_2 = {52 74 6c 41 c7 45 ?? 64 64 46 75 c7 45 ?? 6e 63 74 69 c7 45 ?? 6f 6e 54 61 66 c7 ?? ?? 62 6c e8 ?? ?? ?? ?? b9 b5 41 d9 5e 48 8b d8 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Shelcorid_B_2147914728_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelcorid.B"
        threat_id = "2147914728"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelcorid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 00 00 00 00 58 [0-48] 50 e8 ?? 00 00 00 83 c4 14}  //weight: 5, accuracy: Low
        $x_1_2 = {b9 13 9c bf bd}  //weight: 1, accuracy: High
        $x_1_3 = {b9 b5 41 d9 5e}  //weight: 1, accuracy: High
        $x_1_4 = {b9 49 f7 02 78}  //weight: 1, accuracy: High
        $x_1_5 = {b9 58 a4 53 e5}  //weight: 1, accuracy: High
        $x_1_6 = {b9 10 e1 8a c3}  //weight: 1, accuracy: High
        $x_1_7 = {b9 af b1 5c 94}  //weight: 1, accuracy: High
        $x_1_8 = {b9 33 00 9e 95}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win64_Shelcorid_B_2147914728_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelcorid.B"
        threat_id = "2147914728"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelcorid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 00 00 00 00 59 [0-64] c7 44 24 ?? ?? 00 00 00 e8 ?? 00 00 00 48 89 f4}  //weight: 5, accuracy: Low
        $x_1_2 = {b9 13 9c bf bd}  //weight: 1, accuracy: High
        $x_1_3 = {b9 b5 41 d9 5e}  //weight: 1, accuracy: High
        $x_1_4 = {b9 49 f7 02 78}  //weight: 1, accuracy: High
        $x_1_5 = {b9 58 a4 53 e5}  //weight: 1, accuracy: High
        $x_1_6 = {b9 10 e1 8a c3}  //weight: 1, accuracy: High
        $x_1_7 = {b9 af b1 5c 94}  //weight: 1, accuracy: High
        $x_1_8 = {b9 33 00 9e 95}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

