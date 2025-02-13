rule VirTool_Win64_SyzEop_A_2147838157_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/SyzEop.A!MTB"
        threat_id = "2147838157"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SyzEop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 41 b8 07 00 00 00 ba 00 00 00 80 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 89 45 28}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 4c 8b 4d 08 4c 8d ?? ?? ?? ?? ?? 33 d2 33 c9 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 45 48 48 8b 00 48 c7 44 24 38 00 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 4c 24 30 48 8b 8d e8 00 00 00 48 89 4c 24 28 48 c7 44 24 20 00 00 00 00 45 33 c9 4c 8b 45 68 48 8b 95 88 00 00 00 48 8b 4d 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

