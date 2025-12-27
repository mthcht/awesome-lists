rule VirTool_Win64_HuntingSnakes_M_2147945828_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/HuntingSnakes.M"
        threat_id = "2147945828"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "HuntingSnakes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c2 48 8b 85 ?? ?? ?? ?? 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 48 89 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 48 98 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 45 28 48 01 d0 8b 00 48 63 d0 48 8b 45 30 48 01 d0 0f b6 00 88 45 fb}  //weight: 1, accuracy: Low
        $x_1_3 = {48 c7 44 24 20 ?? ?? ?? ?? 4d 89 c1 49 89 c8 48 89 c1 41 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_HuntingSnakes_N_2147946983_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/HuntingSnakes.N"
        threat_id = "2147946983"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "HuntingSnakes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dhanushgowda" ascii //weight: 1
        $x_1_2 = {2e 64 6c 6c 00 63 6f 6f 6c 62 6f 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_HuntingSnakes_D_2147947042_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/HuntingSnakes.D"
        threat_id = "2147947042"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "HuntingSnakes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 f0 41 b9 ?? ?? ?? ?? 41 b8 00 10 00 00 ba ?? ?? ?? ?? b9 ?? ?? ?? ?? ff d0 48 89 45 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 e0 48 8b 45 e0 48 8b 40 60 48 89 45 e8 48 8b 45 e8 48 8b 40 18 48 89 45 d8 48 8b 45 d8 48 83 c0 10 48 89 45 d0}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 54 24 28 48 8b 55 10 48 89 54 24 20 41 b9 ?? ?? ?? ?? 41 b8 ?? ?? ?? ?? ba ?? ?? ?? ?? 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 45 f8 ba ?? ?? ?? ?? 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b 45 e8 ba ?? ?? ?? ?? 48 89 c1 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

