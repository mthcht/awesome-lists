rule VirTool_Win64_Parlsz_A_2147844669_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Parlsz.A!MTB"
        threat_id = "2147844669"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Parlsz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 7c 24 28 33 d2 48 89 85 44 02 00 00 c7 85 40 02 00 00 01 00 00 00 c7 85 4c 02 00 00 02 00 00 00 4c 89 7c 24 20 ff}  //weight: 1, accuracy: High
        $x_1_2 = {44 89 7d b8 45 33 c0 33 d2 49 8b cd ff}  //weight: 1, accuracy: High
        $x_1_3 = {44 8b cb 48 8b d7 48 8b f0 49 8b cd 48 8d ?? ?? 4c 8b c6 48 89 44 24 20 ff 15 5d 1c 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {49 8b d7 48 8d ?? ?? ?? ?? ?? 48 89 44 24 40 48 8d ?? ?? ?? ?? ?? 89 7c 24 38 4c 89 74 24 30 c7 44 24 28 08 00 00 00 48 89 44 24 20 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

