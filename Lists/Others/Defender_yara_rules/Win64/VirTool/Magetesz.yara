rule VirTool_Win64_Magetesz_A_2147981498_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Magetesz.A"
        threat_id = "2147981498"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Magetesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc c1 e0 05 89 c2 48 8b 45 10 48 01 d0 0f b6 00 3c 4c ?? ?? ?? ?? ?? ?? 8b 45 fc c1 e0 05 89 c0 ?? ?? ?? ?? 48 8b 45 10 48 01 d0 0f b6 00 3c 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 00 89 c2 48 8b 45 28 48 01 d0 48 89 45 e0 48 8b 45 d8 48 89 c1 e8 ?? ?? ?? ?? 39 45 30 ?? ?? 48 8b 55 20 48 8b 45 e0 48 89 c1 e8 ?? ?? ?? ?? 84 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

