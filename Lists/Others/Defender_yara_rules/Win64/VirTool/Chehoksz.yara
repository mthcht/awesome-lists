rule VirTool_Win64_Chehoksz_A_2147922939_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Chehoksz.A!MTB"
        threat_id = "2147922939"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Chehoksz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 94 24 88 00 00 00 48 8b 8c 24 80 00 00 00 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? 8b d0 [0-36] 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 4c 8b 8c 24 88 00 00 00 45 33 c0 33 d2 48 8b 8c 24 80 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {88 84 24 38 01 00 00 c6 84 24 39 01 00 00 ff c6 84 24 3a 01 00 00 d0 c6 84 24 3b 01 00 00 48 c6 84 24 3c 01 00 00 89 c6 84 24 3d 01 00 00 ec c6 84 24 3e 01 00 00 5d c6 84 24 3f 01 00 00 c3 c6 84 24 40 01 00 00 cc c6 84 24 41 01 00 00 cc c6 84 24 42 01 00 00 cc 48 c7 44 24 20 00 00 00 00 41 b9 83 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 44 24 28 0f b6 44 24 50 85 c0 ?? ?? 48 83 7c 24 28 00 ?? ?? 48 83 7c 24 28 00 ?? ?? 48 83 7c 24 40 ff ?? ?? b2 01 48 8b 4c 24 48 ?? ?? ?? ?? ?? 48 89 44 24 28 4c 8b 44 24 28 48 8b 54 24 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

