rule VirTool_Win64_Tekelesz_A_2147981496_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Tekelesz.A"
        threat_id = "2147981496"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Tekelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 74 24 ?? 48 8b 7c 24 ?? 49 39 fe ?? ?? 8b 2f ba ?? ?? ?? ?? 4c 89 e9 41 89 e8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 02 49 89 cc 48 89 d3 48 39 42 08 ?? ?? ?? ?? ?? ?? c7 44 24 28 80 00 00 00 45 31 c9}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 2c 01 00 00 ff 15 ?? ?? ?? ?? 48 8b 4c 24 48 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 44 24 40 48 92 e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

