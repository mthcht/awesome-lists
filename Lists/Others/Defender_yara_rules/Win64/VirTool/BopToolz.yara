rule VirTool_Win64_BopToolz_A_2147844665_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/BopToolz.A!MTB"
        threat_id = "2147844665"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "BopToolz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 04 00 00 00 48 89 44 24 20 33 d2 c7 45 33 02 00 00 00 ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 4c 24 38 48 8d ?? ?? ?? 41 b9 19 00 02 00 48 89 44 24 20 41 b8 0c 00 00 00 48 8d ?? ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 4c 24 30 48 8d ?? ?? ?? ?? ?? c7 44 24 28 04 00 00 00 48 8d ?? ?? ?? ?? ?? 41 b9 04 00 00 00 48 89 44 24 20 45 33 c0 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {48 33 c4 48 89 45 4f 48 8b 0d 75 64 00 00 4c 8d ?? ?? 48 c7 c2 02 00 00 80 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {45 33 c0 48 8b d0 48 8b 4c 24 70 ff 15 ?? ?? ?? ?? 8b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

