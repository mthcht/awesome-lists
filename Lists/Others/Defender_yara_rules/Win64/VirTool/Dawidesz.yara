rule VirTool_Win64_Dawidesz_A_2147853085_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dawidesz.A!MTB"
        threat_id = "2147853085"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dawidesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 7c 24 50 0f 11 01 88 41 10 33 c0 0f 57 c0 48 89 44 24 70 48 b8 00 00 00 00 10 10 00 00 48 c7 45 10 11 01 00 00 0f 11 45 90}  //weight: 1, accuracy: High
        $x_1_2 = {0f 11 41 80 0f 10 40 a0 0f 11 49 90 0f 10 48 b0 0f 11 41 a0 0f 10 40 c0 0f 11 49 b0 0f 10 48 d0 0f 11 41 c0 0f 10 40 e0 0f 11 49 d0 0f 10 48 f0 0f 11 41 e0 0f 11 49 f0 48 83 ea 01 75 ad}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b d8 ff 15 ?? ?? ?? ?? 48 8b c8 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 ?? ?? ?? ?? 45 33 c9 48 89 4c 24 48 45}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b cb e8 ?? ?? ?? ?? 48 ?? ?? ?? ff 15 ?? ?? ?? ?? 48 81 45 08 00 e1 f5 05 48 ?? ?? ?? b1 01 ff 15 ?? ?? ?? ?? 85 c0 79}  //weight: 1, accuracy: Low
        $x_1_5 = {48 89 bc 24 a0 02 00 00 ff 15 ?? ?? ?? ?? 8b d8 ff 15 ?? ?? ?? ?? 4c ?? ?? ?? ?? ba 20 00 00 00 48 8b c8 ff 15 ?? ?? ?? ?? 33 ff 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

