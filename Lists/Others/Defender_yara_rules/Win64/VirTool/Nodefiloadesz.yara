rule VirTool_Win64_Nodefiloadesz_A_2147912621_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Nodefiloadesz.A!MTB"
        threat_id = "2147912621"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Nodefiloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 4d b8 48 89 7d ?? 89 7d b0 ?? ?? ?? ?? 48 89 44 24 40 ?? ?? ?? ?? 48 89 44 24 38 48 89 7c 24 30 c7 44 24 28 ?? ?? ?? ?? 89 7c 24 20 45 33 c9 45 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 47 10 48 89 4d e0 48 89 45 e8 0f 10 45 e0 0f 11 45 b0 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 98 48 c7 45 e0 02 00 00 00 ?? ?? ?? ?? 48 89 45 e8 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 30 48 c7 44 24 38 ?? ?? ?? ?? 0f 28 45 e0 66 0f 7f 45 e0 0f 28 4c 24 30 66 0f 7f 4c 24 30}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 84 24 a0 01 00 00 41 b8 [0-17] 48 8b 9c 24 88 01 00 00 48 8b cb ?? ?? ?? ?? ?? ?? 48 8b c8 48 85 c0 ?? ?? 88 84 24 a0 01 00 00 48 8b 8c 24 98 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

