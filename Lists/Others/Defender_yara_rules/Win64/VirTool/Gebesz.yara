rule VirTool_Win64_Gebesz_A_2147974559_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Gebesz.A"
        threat_id = "2147974559"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Gebesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 50 08 4c 8b 08 48 83 fa 03 ?? ?? 48 83 fa 02 ?? ?? 66 41 81 39 77 67 ?? ?? ?? ?? ?? ?? 48 8b 94 24 a8 00 00 00 ?? ?? ?? ?? ?? 48 83 fa 03}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b 94 24 ?? 00 00 00 66 41 81 3a 64 6e ?? ?? 41 80 7a 02 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

