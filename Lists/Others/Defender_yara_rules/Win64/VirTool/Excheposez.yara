rule VirTool_Win64_Excheposez_A_2147907207_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Excheposez.A!MTB"
        threat_id = "2147907207"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Excheposez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 7d a0 48 83 ff 06 ?? ?? ?? ?? ?? ?? 4c 8b c7 [0-18] 85 c0 ?? ?? ?? ?? ?? ?? 33 d2 41 b8 00 01 00 00 [0-18] 33 d2 41 b8 00 01 00 00 [0-18] 33 ff 89 7c 24 78 [0-22] 48 8b c8 ?? ?? ?? ?? ba ff 01 0f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 7d d7 0f 57 c0 0f 11 45 e7 48 89 7d f7 48 c7 45 ff 0f 00 00 00 40 88 7d e7 0f 11 45 07 48 89 7d 17 48 c7 45 1f 07 00 00 00 66 89 7d 07 ?? ?? ?? ?? ?? ?? ?? ?? bb 01 00 00 00 8b d3 33 c9 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

