rule VirTool_Win64_Encledosz_A_2147906322_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Encledosz.A!MTB"
        threat_id = "2147906322"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Encledosz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 7c 24 30 ?? ?? ?? ?? ?? ?? 48 8b c8 ?? ?? ?? ?? ?? 48 8b f8 48 85 c0 ?? ?? ?? ?? ?? ?? 48 8b d0 48 89 5c 24 48 [0-18] 33 c9 ba 00 10 00 00 44 8b c2 [0-16] 33 d2 41 b8 f8 0f 00 00 48 8b d8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 40 00 00 00 00 c7 03 10 00 00 00 c7 43 04 00 00 10 00 ?? ?? ?? ?? ?? ?? 41 b9 08 00 00 00 4c 8b c3 48 8b c8 48 8b d7 ?? ?? ?? ?? ?? 48 89 44 24 20 ?? ?? ?? ?? ?? ?? 48 8b d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

