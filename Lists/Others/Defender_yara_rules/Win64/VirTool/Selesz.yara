rule VirTool_Win64_Selesz_A_2147981850_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Selesz.A"
        threat_id = "2147981850"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Selesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 b8 48 8b 95 e0 01 00 00 89 4c 24 28 ?? ?? ?? ?? 48 89 4c 24 20 41 b9 01 00 00 00 41 b8 00 00 00 00 48 89 c1 48 8b ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 89 c1 48 8b ?? ?? ?? ?? ?? ff ?? 66 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {55 48 81 ec 70 02 00 00 [0-34] 41 b8 04 01 00 00 48 89 c2 48 8b ?? ?? ?? ?? ?? ff ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

