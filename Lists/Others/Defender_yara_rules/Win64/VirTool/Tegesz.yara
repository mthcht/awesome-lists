rule VirTool_Win64_Tegesz_A_2147982447_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Tegesz.A"
        threat_id = "2147982447"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Tegesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 54 24 60 ?? ?? ?? ?? 41 b9 94 00 00 00 48 89 44 24 20 4c 8b c3 48 8b ce ff ?? ?? ?? ?? ?? 44 8b f8 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 44 24 60 ?? ?? ?? ?? ?? 48 89 44 24 68 [0-16] 48 c7 44 24 70 94 00 00 00 41 b9 20 00 00 00 48 89 44 24 20 48 8b ce ff [0-18] 44 8b f8 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {45 33 c9 48 c7 44 24 20 00 00 00 00 45 33 c0 49 8b d7 49 8b ce ff [0-18] 44 8b e0 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

