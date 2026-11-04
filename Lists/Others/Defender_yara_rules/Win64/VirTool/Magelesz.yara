rule VirTool_Win64_Magelesz_A_2147981497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Magelesz.A"
        threat_id = "2147981497"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Magelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 60 48 89 4d 10 48 89 55 18 c7 45 cc 4c 8b d1 b8 48 c7 45 f8 04 00 00 00 c7 45 f4 00 00 00 00 48 8b 45 18 48 89 45 e8}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 45 f8 ?? ?? ?? ?? ?? ?? ?? 48 8b 55 f0 48 89 54 24 20 48 89 c2 e8 ?? ?? ?? ?? 84 c0 ?? ?? ba a2 07 c0 36 b9 01 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {55 48 89 e5 48 83 ec 30 89 4d 10 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 10 89 45 fc ba 7e cd 07 0e b9 01 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

