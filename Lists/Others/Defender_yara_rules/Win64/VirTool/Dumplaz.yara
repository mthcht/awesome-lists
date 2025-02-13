rule VirTool_Win64_Dumplaz_A_2147832714_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dumplaz.A!MTB"
        threat_id = "2147832714"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dumplaz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 8d d0 06 00 00 ff 15 ?? ?? ?? ?? 89 85 34 04 00 00 48 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 41 b9 02 00 00 00 4c 8b 85 18 04 00 00 8b 95 34 04 00 00 48 8b 8d d0 06 00 00 e8 ?? ?? ?? ?? 89 85 54 04 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 d8 01 00 00 8b 00 39 85 54 02 00 00 0f 83 ?? ?? ?? ?? 8b 85 54 02 00 00 48 6b c0 18 48 8d ?? ?? ?? ?? ?? 48 8b 95 d8 01 00 00 48 8b f9 48 8d ?? ?? ?? b9 18 00 00 00 f3 a4 48 c7 85 c8 02 00 00 00 00 00 00 83 bd 98 02 00 00 04}  //weight: 1, accuracy: Low
        $x_1_3 = {44 8b 85 98 02 00 00 33 d2 b9 40 00 00 00 ff 95 ?? ?? ?? ?? 48 89 85 38 02 00 00 ff 15 ?? ?? ?? ?? 0f b7 8d 9e 02 00 00 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 10 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

