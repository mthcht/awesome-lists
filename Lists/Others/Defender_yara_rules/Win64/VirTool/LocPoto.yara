rule VirTool_Win64_LocPoto_A_2147844660_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/LocPoto.A!MTB"
        threat_id = "2147844660"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "LocPoto"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 45 33 c9 4c 8d ?? ?? ?? ?? ?? 33 d2 33 c9 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {89 44 24 20 44 8b 8d 78 01 00 00 4c 8b 85 70 01 00 00 48 8b 95 68 01 00 00 48 8b 8d 60 01 00 00 ff}  //weight: 1, accuracy: High
        $x_1_3 = {45 33 c9 45 33 c0 ba 0a 00 00 00 33 c9 ff}  //weight: 1, accuracy: High
        $x_1_4 = {48 8b 45 28 48 83 c0 20 41 b8 08 00 00 00 48 8b d0 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 0d 2c 85 01 00 ff}  //weight: 1, accuracy: Low
        $x_1_5 = {33 c9 ff 15 ?? ?? ?? ?? 48 8b 45 08 48 8b 00 4c 8d ?? ?? ?? ?? ?? 45 33 c0 48 8b 55 28 48 8b 4d 08 ff}  //weight: 1, accuracy: Low
        $x_1_6 = {b9 00 20 00 00 ff 15 ?? ?? ?? ?? 48 89 85 a8 00 00 00 b9 00 20 00 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

