rule VirTool_Win64_CoffLdz_A_2147839558_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CoffLdz.A!MTB"
        threat_id = "2147839558"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CoffLdz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 85 48 04 00 00 48 8b 85 48 04 00 00 8b 40 04 48 6b c0 12 48 8b 8d e8 01 00 00 48 03 c8 48 8b c1 48 89 85 68 04 00 00 48 8b 85 68 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 85 24 05 00 00 48 6b c0 18 48 8b 4d 68 48 8b 44 01 08 48 8b 8d 88 00 00 00 48 03 c8 48 8b c1 48 89 85 e8 04 00 00 8b 85 24 05 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 b8 20 00 00 00 48 8b 95 68 01 00 00 48 8b 8d 48 01 00 00 ff 15 ?? ?? ?? ?? 48 8b 85 28 01 00 00 48 89 44 24 28}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 24 48 6b c0 12 48 8b 4d 08 48 03 c8 48 8b c1 48 89 45 48 c7 45 64 00 00 00 00 48 c7 85 88 00 00 00 00 00 00 00 b8 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {48 c7 45 08 00 00 00 00 41 b8 08 00 00 00 48 8b 95 00 01 00 00 48 8d 4d 08 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

