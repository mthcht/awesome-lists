rule VirTool_Win64_Shredesz_A_2147971789_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shredesz.A"
        threat_id = "2147971789"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shredesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c7 48 89 de ?? ?? ?? ?? ?? ?? ?? 41 b9 0d 00 00 00 48 89 d0 ?? ?? ?? ?? ?? ?? ?? 66 ?? e8 ?? ?? ?? ?? 48 89 84 24 60 01 00 00 48 8b ?? ?? ?? ?? ?? 48 89 94 24 a8 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 84 24 58 01 00 00 48 8b ?? ?? ?? ?? ?? 48 89 94 24 a0 01 00 00 48 8b ?? ?? ?? ?? ?? 48 89 94 24 d8 00 00 00 ?? ?? ?? ?? ?? ?? ?? bb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

