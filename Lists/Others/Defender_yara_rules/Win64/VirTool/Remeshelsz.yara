rule VirTool_Win64_Remeshelsz_A_2147900125_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Remeshelsz.A"
        threat_id = "2147900125"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Remeshelsz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 68 00 00 00 ba 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? c7 05 52 5c ?? ?? ?? ?? ?? ?? c7 05 84 5c ?? ?? ?? ?? ?? ?? 48 8b 05 19 5c 00 00 48 89 05 9a ?? ?? ?? 48 8b 05 93}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c1 48 8b ?? ?? ?? ?? ?? ?? ?? 89 05 9b 5c 00 00 48 8b 05 88 5c 00 00 48 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 48 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

