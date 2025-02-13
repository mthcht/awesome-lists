rule VirTool_Win64_GMimitz_A_2147838744_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/GMimitz.A!MTB"
        threat_id = "2147838744"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "GMimitz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 30 48 89 6c 24 28 48 8d ?? ?? ?? 48 8b 15 51 84 31 00 48 8b 35 52 84 31 00 31 c0 eb 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {44 0f b6 04 02 4c 8b 0d 46 84 31 00 48 8b 0d 47 84 31 00 48 39 c8 72 d4}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 44 24 20 31 db 31 c9 48 89 cf e8}  //weight: 1, accuracy: High
        $x_1_4 = {46 0f b6 14 08 45 31 c2 45 88 14 01 48 ff c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

