rule VirTool_Win64_ReclReg_A_2147839552_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/ReclReg.A!MTB"
        threat_id = "2147839552"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ReclReg"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 5c 24 30 c7 44 24 28 80 00 00 00 ba 16 01 12 00 48 89 5c 24 20 0f 11 45 b8 48 89 5d 88 c7 45 98 40 00 00 00 48 89 45 90 f3 0f 7f 45 a0 ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 5c 24 60 41 b9 06 00 02 00 48 89 44 24 20 45 33 c0 48 8d ?? ?? ?? ?? ?? 48 c7 c1 00 00 00 80 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 44 24 40 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? 45 33 c9 48 89 44 24 38 45 33 c0 48 89 5c 24 30 c7 44 24 28 3f 00 0f 00 89 5c 24 20 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 4c 24 68 48 8d ?? ?? ?? ?? ?? 89 7c 24 28 41 b9 01 00 00 00 45 33 c0 48 89 44 24 20 33 d2 ff}  //weight: 1, accuracy: Low
        $x_1_5 = {45 33 c9 45 0f b7 c5 48 8b d6 48 8b c8 ff 15 ?? ?? ?? ?? 4c 8b e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

