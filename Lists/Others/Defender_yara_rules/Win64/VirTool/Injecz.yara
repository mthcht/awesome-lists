rule VirTool_Win64_Injecz_A_2147838739_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injecz.A!MTB"
        threat_id = "2147838739"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injecz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 0f 11 7c 24 20 48 8d ?? ?? ?? ?? ?? 48 89 54 24 20 48 89 44 24 28 48 8d ?? ?? ?? 48 89 54 24 40 c6 44 24 1b 01 48 8b 5c 24 58 48 8b 4c 24 60 e8 b5 ?? ?? ?? 48 85 db}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 1d 10 2f 2c 00 48 89 5c 24 58 0f 1f 00 e8 bb ?? ?? ?? 48 85 c9 0f 85 51 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 4c 24 40 48 89 08 48 8b 54 24 48 48 89 50 08 48 8b 5c 24 70 48 89 58 10 48 8b 5c 24 58 48 89 58 18 48 8b 35 11 98 2c 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 8b 4c 24 40 48 89 08 48 8b 54 24 48 48 89 50 08 48 8b 5c 24 58 48 89 58 10 48 c7 40 18 20 00 00 00 48 8b 5c 24 68 48 89 58 20 48 8b 1d 9c 97 2c 00}  //weight: 1, accuracy: High
        $x_1_5 = {48 8b 4c 24 40 48 89 08 44 0f 11 78 08 48 8b 54 24 48 48 89 50 18 44 0f 11 78 20 48 c7 40 30 00 00 00 00 48 8b 15 18 97 2c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Injecz_B_2147838740_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injecz.B!MTB"
        threat_id = "2147838740"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injecz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 b4 24 40 01 00 00 48 8b b4 24 b8 00 00 00 48 89 b4 24 48 01 00 00 bb 02 00 00 00 48 89 d9 48 8d ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? bb 0b 00 00 00 66 ?? e8 fb ?? ?? ?? 89 44 24 3c 48 85 db}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 8c 24 80 00 00 00 48 89 08 48 8b 54 24 48 48 89 50 08 48 8b 5c 24 40 48 89 58 10 48 8b 5c 24 78 48 89 58 18 48 8b 1d ee c8 0d 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 8c 24 80 00 00 00 48 89 08 48 8b 54 24 48 48 89 50 08 48 8b 9c 24 e0 00 00 00 48 89 58 10 48 8b 5c 24 78 48 89 58 18 48 8b 9c 24 d8 00 00 00 48 89 58 20 48 8b 1d 0d c8 0d 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 8b 8c 24 80 00 00 00 48 89 08 44 0f 11 78 08 48 8b 54 24 58 48 89 50 18 48 8b 54 24 48 48 89 50 20 44 0f 11 78 28 48 8b 15 81 c6 0d 00 48 89 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

