rule VirTool_Win64_Amseosz_A_2147848726_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Amseosz.A!MTB"
        threat_id = "2147848726"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Amseosz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 0f 57 c0 48 8d ?? ?? ?? ?? ?? 48 8b d8 48 8d ?? ?? ?? 33 c0 89 84}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 30 4c 8d ?? ?? ?? 48 8d ?? ?? ?? 41 b9 04 00 00 00 48 8d ?? ?? ?? 48 89 44 24 20 48 8b cf ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b9 01 00 00 00 48 c7 44 24 20 00 00 00 00 4c 8d ?? ?? ?? 48 8b cf ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 4a 08 48 89 bc 24 d0 00 00 00 ff 15 ?? ?? ?? ?? 33 d2 44 8b c0 8d ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

