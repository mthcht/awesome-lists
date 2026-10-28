rule VirTool_Win64_Kernelesz_A_2147981114_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kernelesz.A"
        threat_id = "2147981114"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kernelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c4 48 89 84 24 b0 01 00 00 48 c7 44 24 58 ff ff ff ff c7 44 24 48 00 00 00 00 c7 44 24 60 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 c0 ?? ?? ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 30 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 41 b9 08 00 00 00 ?? ?? ?? ?? ?? ba 0c 20 22 b8 48 8b 4c 24 58 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

