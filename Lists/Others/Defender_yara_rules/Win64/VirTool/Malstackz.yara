rule VirTool_Win64_Malstackz_A_2147844661_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Malstackz.A!MTB"
        threat_id = "2147844661"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Malstackz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b d8 48 81 c3 20 0b 00 00 74 a9}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 28 c7 44 24 20 04 00 00 00 45 33 c9 4c 8b c3 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 8b d8}  //weight: 1, accuracy: Low
        $x_1_3 = {45 33 c9 45 33 c0 33 d2 33 c9 48 8b d8 ff 15 ?? ?? ?? ?? 48 8b f8 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 30 20 00 00 00 44 89 6c 24 28 8b 51 44 48 8d ?? ?? ?? 4c 2b fa 44 89 6c 24 20 48 8b d3 4c 03 f8 ff}  //weight: 1, accuracy: Low
        $x_1_5 = {4c 8b c2 0f 10 48 10 0f 11 01 0f 10 40 20 0f 11 49 10 0f 10 48 30 0f 11 41 20 0f 10 40 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

