rule VirTool_Win64_Kimebesz_A_2147981113_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kimebesz.A"
        threat_id = "2147981113"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kimebesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 30 45 33 c9 89 5c 24 28 ba 00 00 00 c0 41 b8 03 00 00 00 c7 44 24 20 03 00 00 00 ff ?? ?? ?? ?? ?? 48 8b f8 48 83 f8 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 5c 24 38 ?? ?? ?? ?? ?? 48 89 44 24 30 [0-16] c7 44 24 28 04 00 00 00 41 b9 04 00 00 00 48 89 44 24 20 ba 0c 40 22 00 48 8b cf ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

