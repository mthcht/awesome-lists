rule VirTool_Win64_Tokzers_A_2147844681_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Tokzers.A!MTB"
        threat_id = "2147844681"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Tokzers"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 85 00 01 00 00 33 d2 b9 00 04 00 00 ff 15 ?? ?? ?? ?? 48 89 45 08 48 83 7d 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 20 03 00 00 00 45 33 c9 41 b8 02 00 00 00 ba 00 00 00 40 48 8d ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 28 04 00 00 00 48 8d ?? ?? 48 89 44 24 20 41 b9 04 00 00 00 4c 8d ?? ?? ba a4 01 22 00 48 8b 4d 48 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4d 04 e8 ?? ?? ?? ?? 85 c0 75 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

