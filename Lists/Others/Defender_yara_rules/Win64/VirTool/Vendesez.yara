rule VirTool_Win64_Vendesez_A_2147964051_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Vendesez.A"
        threat_id = "2147964051"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Vendesez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 55 88 4c 8b cf 48 8b 4d 80 4c 8b c3 48 89 74 24 20 e8 ?? ?? ?? ?? 85 c0 ?? ?? 89 44 24 60 ?? ?? ?? ?? ?? ?? ?? 48 c7 44 24 78 2d 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {45 33 c0 33 d2 e8 ?? ?? ?? ?? 48 8b 4d 80 ?? ?? ?? ?? 41 b9 00 80 00 00 48 89 75 c8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 4d ?? e8 ?? ?? ?? ?? 48 8b 4d 80 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

