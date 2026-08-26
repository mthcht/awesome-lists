rule VirTool_Win64_Megesz_A_2147977017_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Megesz.A"
        threat_id = "2147977017"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Megesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b c0 48 89 ?? ?? ?? ?? ?? 80 3b e9 ?? ?? ?? ?? ?? ?? 80 7b 20 4c ?? ?? ?? ?? 41 ba 01 00 00 00 ?? ?? 45 8b ca 33 c9 80 7c 0b 20 b8 8b c1}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b9 04 00 00 00 80 3a 4c ?? ?? 33 c9 ?? ?? ?? ?? ?? ?? ?? ?? 80 bc 0b 80 00 00 00 b8 8b c1 ?? ?? ?? ?? ?? ?? ff c1 83 f9 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

