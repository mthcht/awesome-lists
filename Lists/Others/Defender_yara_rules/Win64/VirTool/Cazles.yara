rule VirTool_Win64_Cazles_A_2147835848_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cazles.A!MTB"
        threat_id = "2147835848"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cazles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b f8 33 c0 b9 10 00 00 00 f3 aa c7 45 34 10 00 00 00 48 8d ?? ?? 48 89 44 24 20 41 b9 19 00 02 00 45 33 c0 48 8d ?? ?? ?? ?? ?? 48 c7 c1 02 00 00 80 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {05 d8 00 00 00 66 89 45 54 48 c7 85 e0 00 00 00 c4 00 00 00 0f b7 45 54 66 89 85 e2 00 00 00 ff 15 ?? ?? ?? ?? 8b c0 48 89 85 e8 00 00 00 ff 15 ?? ?? ?? ?? 8b c0}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 85 04 07 00 00 39 85 64 07 00 00 ?? ?? b9 04 00 00 00 ff 15 ?? ?? ?? ?? 48 89 85 a8 05 00 00 48 63 85 64 07 00 00 48 8b 8d 48 07 00 00 0f b6 04 01 44 8b c8 4c 8d ?? ?? ?? ?? ?? ba 04 00 00 00 48 8b 8d a8 05 00 00 e8 ?? ?? ?? ?? 4c 8b 8d 88 05 00 00 41 b8 01 00 00 00 ba 02 00 00 00 48 8b 8d a8 05 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

