rule VirTool_Win64_Plashelln_A_2147844673_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Plashelln.A!MTB"
        threat_id = "2147844673"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Plashelln"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 04 00 00 00 41 b8 00 10 00 00 48 8b 45 08 48 8b 50 08 48 8b 8d 00 01 00 00 ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 48 10 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 98 48 8b 4d 08 48 8b 49 08 48 ff c1 33 d2 48 f7 f1 48 8b c2 48 8b 4d 08 89 41 04}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 85 e0 00 00 00 8b 40 04 48 8b 8d e0 00 00 00 48 03 41 10 4c 8b 85 f0 00 00 00 48 8b 95 e8 00 00 00 48 8b c8 e8}  //weight: 1, accuracy: High
        $x_1_4 = {48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 45 33 c9 4c 8b 45 28 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 89 45 48}  //weight: 1, accuracy: Low
        $x_1_5 = {4c 8b 85 e0 00 00 00 ba 08 00 00 00 48 8b c8 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

