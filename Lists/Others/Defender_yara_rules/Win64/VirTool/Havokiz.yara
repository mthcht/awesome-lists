rule VirTool_Win64_Havokiz_C_2147833816_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Havokiz.C!MTB"
        threat_id = "2147833816"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 d1 48 89 c8 45 31 c0 44 0f b6 08 41 ff c0 48 83 c0 04 47 8a 0c 0c 44 88 48 fc 41 80 f8 04 ?? ?? 48 ff c1 49 39 cd ?? ?? 8a 4c 24 35 8a 44 24 31 88 4c 24 31 8a 4c 24 39 88 4c 24 35 8a 4c 24 3d 88 44 24 3d 8a 44 24 32 88 4c 24 39 8a 4c 24 3a 88 44 24 3a 8a 44 24 36 88 4c 24 32 8a 4c 24 3e 88 44 24 3e 8a 44 24 33 88 4c 24 36 8a 4c 24 3f 88 4c 24 33 8a 4c 24 3b 88 4c 24 3f 8a 4c 24 37 88 44 24 37 88 4c 24 3b 41 83 fe}  //weight: 1, accuracy: Low
        $x_1_2 = {43 8a 34 02 45 8a 04 12 41 8a 14 02 43 8a 04 0a 45 89 d9 41 c1 e9 03 42 32 34 0b 41 89 f1 ?? ?? 83 fe 04 ?? ?? 47 8a 0c 0a 47 8a 04 02 41 8a 14 12 41 8a 04 02 44 32 09 44 32 41 01 41 ff c3 48 83 c1 04 32 51 fe 32 41 ff 44 88 49 1c 44 88 41 1d 88 51 1e 88 41 1f 41 83 fb 3c ?? ?? 5b 5e c3}  //weight: 1, accuracy: Low
        $x_1_3 = {56 31 c0 53 44 8a 04 02 44 88 04 01 44 8a 44 02 01 44 88 44 01 01 44 8a 44 02 02 44 88 44 01 02 44 8a 44 02 03 44 88 44 01 03 48 83 c0 04 48 83 f8 20 ?? ?? 41 bb 08 00 00 00 4c 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 50 40 4c 8b 40 34 48 89 d1 49 8b 14 d0 48 85 d2 ?? ?? ff c1 89 48 40 ?? ?? c7 40 40 00 00 00 00 49 8b 10 ?? ?? 31 d2 ff c9 ?? ?? 4c 8b 60 34 31 ff 89 f8 49 83 3c c4 00 ?? ?? ff c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Havokiz_D_2147833817_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Havokiz.D!MTB"
        threat_id = "2147833817"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 b8 61 6d 73 69 2e 64 6c 6c 41 54 56 53 48 83 ec 70 48 8d ?? ?? ?? 66 c7 44 24 6e 00 00 c7 44 24 4a b8 57 00 07 66 c7 44 24 4e 80 c3 48 89 44 24 66 e8 ?? ?? ?? ?? ba 8e d1 fc 29 48 89 c1 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 ec 58 48 63 41 3c 89 94 24 a8 00 00 00 48 c7 44 24 38 00 00 00 00 48 01 c8 48 c7 44 24 40 00 00 00 00 8b 98 88 00 00 00 48 c7 44 24 48 00 00 00 00 8b 80 8c 00 00 00 48 01 cb 8b 73 20 44 8b 6b 1c 89 44 24 2c 44 8b 73 24 44 39 7b 18 0f 86 ?? ?? ?? ?? 44 89 ff 49 8d ?? ?? 8b 2c 30 4c 01 e5 48 89 e9 e8 ?? ?? ?? ?? 3b 84 24 a8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 5b 48 83 c4 08 48 8b 44 24 18 4c 8b 10 4c 89 14 24 4c 8b 50 08 4c 89 58 08 48 89 58 10 48 8d [0-5] 48 89 18 48 89 c3 41 ff e2}  //weight: 1, accuracy: Low
        $x_1_4 = {48 83 ec 10 48 89 d9 48 8b 59 10 ff 61 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Havokiz_2147841136_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Havokiz.x!MTB"
        threat_id = "2147841136"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "x: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {ff c1 3e 66 [0-1] 75 ef 48 31 c0 66 8b 41 3c 48 01 c8 48 31 db 66 81 c3 ?? ?? 3e 66 3b 18 75 d7 48}  //weight: 7, accuracy: Low
        $x_7_2 = {48 ff c1 3e 66 3b 19 75 ef 48 31 c0 66 8b 41 3c 48 01 c8 48 31 db 66 81 c3 50 45 3e 66 3b 18 75 d7 48 89 c8 c3}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win64_Havokiz_Z_2147841480_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Havokiz.Z!MTB"
        threat_id = "2147841480"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {48 ff c1 3e 66 3b 19 75 ef 48 31 c0 66 8b 41 ?? 48 01 c8 48 31 db 66 81 c3 ?? ?? 3e 66 3b 18 75 d7 48 89 c8 c3}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Havokiz_E_2147894333_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Havokiz.E!MTB"
        threat_id = "2147894333"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 d1 48 89 c8 45 31 c0 44 0f b6 08 41 ff c0 48 83 c0 04 47 8a 0c 0c 44 88 48 fc 41 80 f8 04 ?? ?? 48 ff c1 49 39 cd ?? ?? 8a 4c 24 35 8a 44 24 31 88 4c 24 31 8a 4c 24 39 88 4c 24 35 8a 4c 24 3d 88 44 24 3d 8a 44 24 32 88 4c 24 39 8a 4c 24 3a 88 44 24 3a 8a 44 24 36 88 4c 24 32 8a 4c 24 3e 88 44 24 3e 8a 44 24 33 88 4c 24 36 8a 4c 24 3f 88 4c 24 33 8a 4c 24 3b 88 4c 24 3f 8a 4c 24 37 88 44 24 37 88 4c 24 3b 41 83 fe}  //weight: 1, accuracy: Low
        $x_1_2 = {43 8a 34 02 45 8a 04 12 41 8a 14 02 43 8a 04 0a 45 89 d9 41 c1 e9 03 42 32 34 0b 41 89 f1 ?? ?? 83 fe 04 ?? ?? 47 8a 0c 0a 47 8a 04 02 41 8a 14 12 41 8a 04 02 44 32 09 44 32 41 01 41 ff c3 48 83 c1 04 32 51 fe 32 41 ff 44 88 49 1c 44 88 41 1d 88 51 1e 88 41 1f 41 83 fb 3c ?? ?? 5b 5e c3}  //weight: 1, accuracy: Low
        $x_1_3 = {56 31 c0 53 44 8a 04 02 44 88 04 01 44 8a 44 02 01 44 88 44 01 01 44 8a 44 02 02 44 88 44 01 02 44 8a 44 02 03 44 88 44 01 03 48 83 c0 04 48 83 f8 20 ?? ?? 41 bb 08 00 00 00 4c 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 74 24 78 48 ?? ?? ?? ?? 45 31 c0 48 89 d9 c7 44 24 28 40 00 00 00 48 ?? ?? ?? ?? 49 89 f1 c7 44 24 20 00 30 00 00 e8 ?? ?? ?? ?? 85 c0 0f 88 df 00 00 00 4c 8b 4c 24 78 48 8b 54 24 70 49 89 f8 48 89 d9 48 c7 44 24 20 00 00 00 00 e8 ?? ?? ?? ?? 85 c0 0f 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

