rule VirTool_Win64_Rebesz_A_2147976422_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rebesz.A"
        threat_id = "2147976422"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rebesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 31 d2 45 31 c9 31 d2 4c 89 4c 24 28 ?? ?? ?? ?? ?? ?? ?? 45 31 c9 31 c9 44 89 54 24 20 ff [0-18] 48 89 ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b8 04 01 00 00 ?? ?? ?? ?? ?? 31 c9 ff [0-23] ba 00 04 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ff [0-19] e8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 d9 e8 ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 83 fe 70 ?? ?? ?? ?? ?? ?? 80 7b 01 73 ?? ?? ?? ?? ?? ?? 80 7b 02 00 [0-19] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

