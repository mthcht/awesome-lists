rule VirTool_Win64_Admisez_A_2147847059_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Admisez.A!MTB"
        threat_id = "2147847059"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Admisez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 89 d0 49 89 cc 31 d2 b9 00 04 00 00 ff 15 ?? ?? ?? ?? 49 89 c5 48 85 c0 0f 84 f9 01 00 00 4c 8d ?? ?? ?? ba 08 00 00 00 48 89 c1 48 c7 44 24 50 00 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 75 3e}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 28 c7 44 24 20 01 00 00 00 ff 15 ?? ?? ?? ?? 48 8b 4c 24 58 45 31 c9 49 89 d8 48 89 7c 24 40 ba 01 00 00 00 48 89 74}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 44 24 20 ff 15 ?? ?? ?? ?? 8b 4c 24 40 e8 ?? ?? ?? ?? 31 c9 48 89 74 24 20 4d 89 f8 49 89}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 89 fa 4c 89 e9 e8 ?? ?? ?? ?? 85 c0 74 17 48 8d ?? ?? ?? ?? ?? 4c 89 e9 e8 ?? ?? ?? ?? 85 c0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Admisez_B_2147892463_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Admisez.B!MTB"
        threat_id = "2147892463"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Admisez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 44 24 68 00 00 00 00 48 c7 44 24 58 00 00 00 00 ff 15 ?? ?? ?? ?? 49 89 c5 48 85 c0 0f 84 ?? ?? ?? ?? 4c ?? ?? ?? ?? ba 00 00 00 02 48 89 c1 4c ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 60 00 00 00 00 48 c7 44 24 68 00 00 00 00 48 c7 44 24 70 00 00 00 00 c7 84 24 80 00 00 00 68 00 00 00 48 89 44 24 28 c7 44 24 20 01 00 00 00 ff 15 ?? ?? ?? ?? 41 89 c4 85}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 48 00 00 00 00 ff ?? 8b 4c 24 48 49 89 ce e8 ?? ?? ?? ?? 45 89 f1 48 89 7c 24 20 48 8b 4c 24 58 49 89 c7 49 89 c0 4c 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 c1 e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 49 89 d8 45 31 c9 ba 01 00 00 00 48 89 44 24 40 48 8b 4c 24 58 48 89 74 24 38 48 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

