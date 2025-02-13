rule VirTool_Win64_Hamesedresz_A_2147916128_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hamesedresz.A!MTB"
        threat_id = "2147916128"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hamesedresz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 48 83 ec 58 ?? ?? ?? ?? ?? ?? 49 89 f0 41 b9 00 30 00 00 31 d2 48 89 c3 c7 44 24 20 40 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? 49 89 f1 49 89 e8 48 89 d9 48 89 c7 ?? ?? ?? ?? ?? 48 89 fa 48 89 44 24 20 ?? ?? ?? ?? ?? ?? 31 c0 31 d2 31 c9 89 54 24 28 49 89 f9 45 31 c0 31 d2 48 89 4c 24 20 48 89 d9 48 89 44 24 30}  //weight: 1, accuracy: Low
        $x_1_2 = {45 31 d2 4c 89 7c 24 48 45 31 c9 45 31 c0 4c 89 74 24 40 31 d2 4c 89 e9 31 f6 4c 89 54 24 38 4c 89 54 24 30 c7 44 24 28 00 00 00 08 c7 44 24 20 01 00 00 00 ?? ?? 85 c0 [0-19] 31 ff 45 31 ed 31 db}  //weight: 1, accuracy: Low
        $x_1_3 = {89 f2 48 89 d9 [0-16] 48 89 d9 89 c2 ?? ?? ?? ?? ?? 8b 53 08 48 8b 0b [0-16] 48 89 c6 48 85 c0 ?? ?? 45 31 ed}  //weight: 1, accuracy: Low
        $x_1_4 = {41 b8 04 01 00 00 48 89 da ?? ?? ?? ?? ?? ?? 85 c0 75 04 31 c0 ?? ?? 48 89 d9 ?? ?? ?? ?? ?? 48 89 c6 48 83 f8 ff ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 89 f1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 d9 ?? ?? ?? ?? ?? 48 89 c6 48 83 f8 ff ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Hamesedresz_B_2147916129_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hamesedresz.B!MTB"
        threat_id = "2147916129"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hamesedresz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 48 83 ec 58 ?? ?? ?? ?? ?? ?? 49 89 f0 41 b9 00 30 00 00 31 d2 48 89 c3 c7 44 24 20 40 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? 49 89 f1 49 89 e8 48 89 d9 48 89 c7 ?? ?? ?? ?? ?? 48 89 fa 48 89 44 24 20 ?? ?? ?? ?? ?? ?? 31 c0 31 d2 31 c9 89 54 24 28 49 89 f9 45 31 c0 31 d2 48 89 4c 24 20 48 89 d9 48 89 44 24 30}  //weight: 1, accuracy: Low
        $x_1_2 = {45 31 d2 4c 89 7c 24 48 45 31 c9 45 31 c0 4c 89 74 24 40 31 d2 4c 89 e9 31 f6 4c 89 54 24 38 4c 89 54 24 30 c7 44 24 28 00 00 00 08 c7 44 24 20 01 00 00 00 ?? ?? 85 c0 [0-19] 31 ff 45 31 ed 31 db}  //weight: 1, accuracy: Low
        $x_1_3 = {31 c9 41 b8 04 01 00 00 48 89 da [0-19] 85 c0 ?? ?? 48 89 d9 ?? ?? ?? ?? ?? 48 89 c6 48 83 f8 ff [0-20] 31 c0 [0-23] 48 89 f1 [0-18] 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {89 f2 48 89 d9 [0-16] 48 89 d9 89 c2 ?? ?? ?? ?? ?? 48 8b 0b 8b 53 08 [0-23] 48 89 c6 48 85 c0 ?? ?? 48 89 c1 [0-18] 48 89 c1 ?? ?? ?? ?? ?? 48 89 c1 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {48 89 f1 4c 8b 4a 28 89 44 24 38 31 c0 48 89 6c 24 40 89 44 24 30 48 8b 02 ba ff 00 00 00 48 89 44 24 28 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 20 ?? ?? ?? ?? ?? 48 89 da 48 89 f1 ?? ?? ?? ?? ?? 48 89 c3 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

