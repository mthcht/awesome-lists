rule VirTool_Win64_Blakout_A_2147850515_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Blakout.A!MTB"
        threat_id = "2147850515"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Blakout"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 ff 01 0f 00 4c 8b 45 48 48 8b 55 48 48 8b 4d 08 ff 15 dc 1c 13 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 45 48 41 b8 02 00 00 00 33 d2 33 c9 ff 15 66 1d 13 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 83 f8 01 0f 84 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 85 14 03 00 00 83 bd 14 03 00 00 00 0f 84 ?? ?? ?? ?? 48 c7 44 24 38 00 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 44 24 30 8b 85 54 03 00 00 89 44 24 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

