rule VirTool_Win64_Epidesz_A_2147973284_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Epidesz.A"
        threat_id = "2147973284"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Epidesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 c0 48 89 85 48 02 00 00 48 8b 4d c8 48 c7 44 24 38 00 00 00 00 c7 44 24 30 00 00 00 00 c7 44 24 28 00 04 00 00 c7 44 24 20 00 04 00 00 48 89 8d 40}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 f1 31 d2 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? e8 ?? ?? ?? ?? 48 89 45 c8 89 55 d0 48 c7 45 c0 01 00 00 00 48 85 c0 ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 11 85 28 02 00 00 ?? ?? ?? ?? ?? ?? ?? e8 [0-17] 31 d2 ff ?? ?? ?? ?? ?? 48 85 c0 [0-19] 48 89 c1 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

