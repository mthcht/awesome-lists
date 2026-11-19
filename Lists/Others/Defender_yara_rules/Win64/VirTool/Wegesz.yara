rule VirTool_Win64_Wegesz_A_2147982448_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Wegesz.A"
        threat_id = "2147982448"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Wegesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 20 ?? ?? ?? ?? ?? 49 8b cf e8 [0-17] 8b f0 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b d8 48 3b c7 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 85 c0 ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b 4d d8 4c 8b c3 48 8b ?? ?? ?? ?? ?? 48 8b cf 48 c7 44 24 20 08 00 00 00 e8 [0-17] 8b f0 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

