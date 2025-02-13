rule VirTool_Win64_Abjector_B_2147782216_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Abjector.B!MTB"
        threat_id = "2147782216"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Abjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 48 8b 04 25 30 00 00 00 48 85 c0 0f 84 [0-4] 48 8b 48 60 48 85 c9 0f 84 [0-8] 48 8b ?? 18}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 0a 84 [0-5] c1 ?? 07 [0-4] 0f be [0-5] 33 ?? 0f b6 ?? 84}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b8 00 30 00 00 [0-3] 44 8d 49 40 [0-5] ?? 0f b7 ?? 14 [0-8] ff}  //weight: 1, accuracy: Low
        $x_1_4 = {ba 01 00 00 00 48 03 [0-4] 44 8b c2 [0-3] ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Abjector_C_2147785107_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Abjector.C!MTB"
        threat_id = "2147785107"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Abjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c9 45 33 c0 33 ?? [0-5] c7 84 24 ?? ?? ?? ?? 1e 00 00 00 [0-5] ?? 89 ?? 24 ?? c7 44 24 ?? 01 00 00 00 ff ?? ?? ?? ?? ?? 83 f8 ff [0-41] 45 33 c9 ?? 03 ?? 44 2b [0-7] ff}  //weight: 1, accuracy: Low
        $x_1_2 = {7e 49 80 3c ?? 20 48 8b ?? 74 ?? ff ?? 48 ff ?? ff 15 ?? ?? ?? ?? 3b ?? 7c e8 [0-25] b2 20 e8 [0-4] 83 f8 01 7e ?? 4c 8d ?? 01 48 63}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 01 00 00 00 85 c0 75 ?? e9 ?? ?? ?? ?? ?? 03 ?? 49 8b ?? 48 8b [0-2] ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

