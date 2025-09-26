rule VirTool_Win64_Gobesesz_A_2147953324_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Gobesesz.A!MTB"
        threat_id = "2147953324"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Gobesesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 9c 24 00 01 00 00 48 89 bc 24 10 01 00 00 48 83 f9 04 ?? ?? 81 3b [0-16] 44 0f 11 bc 24 b8 00 00 00 48 89 f8 48 89 f3 [0-18] 48 89 8c 24 b8 00 00 00 48 89 84 24 c0 00 00 00 48 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 94 24 b0 00 00 00 49 89 c1 49 89 d8 48 89 8c 24 b0 00 00 00 4c 89 84 24 a8 00 00 00 4c 89 8c 24 38 01 00 00 [0-17] b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

