rule VirTool_Win64_Persilesz_A_2147981851_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Persilesz.A"
        threat_id = "2147981851"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Persilesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 44 24 20 00 00 00 00 ?? ?? ?? ?? 44 8b 85 a0 01 00 00 48 8b 95 98 01 00 00 48 8b 4d 08 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 8b 85 a0 01 00 00 39 45 24}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 55 68 48 8b 8d 88 00 00 00 e8 ?? ?? ?? ?? 85 c0 ?? ?? 8b 55 44 48 8b 4d 28 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 28 04 01 00 00 ?? ?? ?? ?? 48 89 44 24 20 ?? ?? ?? ?? ?? ?? ?? 45 33 c0 [0-20] e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

