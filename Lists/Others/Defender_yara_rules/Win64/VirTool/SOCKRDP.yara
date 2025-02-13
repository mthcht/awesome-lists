rule VirTool_Win64_SOCKRDP_A_2147755224_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/SOCKRDP.A!MTB"
        threat_id = "2147755224"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SOCKRDP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 85 d0 47 00 00 48 8d ?? ?? ?? ?? ?? c6 05 d6 59 00 00 04 48 89 05 c7 59 00 00 8b d9 48 8d ?? ?? ?? ?? ?? 48 8b fa 48 8d ?? ?? ?? ?? ?? 48 89 05 a5 59 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 50 44 0f b6 05 03 53 00 00 48 8d ?? ?? ?? ?? ?? 33 f6 41 83 c8 01 83 c9 ff 48 89 74 24 40 ff 15 ?? ?? ?? ?? 48 89 05 e9 52 00 00 48 85 c0 ?? ?? 4c 8d 4c 24 48 48 8b c8 4c 8d 44 24 40 8d 56 01 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8d 0d 88 37 00 00 e8 b3 ?? ?? ?? 45 33 c0 33 d2 33 c9 ff 15 26 23 00 00 45 33 c0 33 d2 33 c9 48 89 05 f8 58 00 00 ff 15 ?? ?? ?? ?? 4c 89 64 24 48 45 33 c9 48 89 05 0b 59 00 00 45 33 c0 33 c0 33 d2 48 89 44 24 50 33 c9 0f 10 44 24 48 48 89 44 24 58 48 89 44 24 60 0f 10 4c 24 58 0f 11 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

