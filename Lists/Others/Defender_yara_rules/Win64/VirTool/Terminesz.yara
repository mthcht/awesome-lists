rule VirTool_Win64_Terminesz_A_2147848725_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Terminesz.A!MTB"
        threat_id = "2147848725"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Terminesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 ff 01 0f 00 4c 8b 45 48 48 8b 55 48 48 8b 4d 08 ff 15 ?? ?? ?? ?? 48 89 45 28 48 83}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 c0 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 89 85 d8 02 00 00 48 83}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 8c 24 f8 01 00 00 48 8b 05 45 3e 12 00 48 33 c5 48 89 85 58 01 00 00 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 89 45 48 41 b8 3f 00 0f 00 33 d2 33 c9 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {41 b8 04 01 00 00 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 7c 8b 85 b8 00 00 00 89 45 04 48 c7 44}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

