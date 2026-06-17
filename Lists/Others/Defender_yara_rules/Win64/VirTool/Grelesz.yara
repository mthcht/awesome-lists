rule VirTool_Win64_Grelesz_A_2147971788_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Grelesz.A"
        threat_id = "2147971788"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Grelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 85 78 06 00 00 4c 89 ad 80 06 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 85 e0 04 00 00 48 c7 85 e8 04 00 00 03 00 00 00 48 c7 85 00 05 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 f9 e8 ?? ?? ?? ?? 83 bd 40 06 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 [0-17] e8 ?? ?? ?? ?? 4c 89 b5 68 06 00 00 4c 89 ad 70 06 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

