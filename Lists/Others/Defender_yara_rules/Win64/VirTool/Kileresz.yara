rule VirTool_Win64_Kileresz_A_2147962847_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kileresz.A"
        threat_id = "2147962847"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kileresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 41 20 48 8b 84 24 b0 00 00 00 48 83 78 20 00 ?? ?? 32 c0 ?? ?? ?? ?? ?? 41 b8 00 00 01 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 84 24 b0 00 00 00 48 8b 48 20 ff ?? ?? ?? ?? ?? 48 89 44 24 70 48 83 7c 24 70 00 ?? ?? 48 8b 4c 24 70 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 41 b8 03 00 00 00 ba 00 00 00 c0 ?? ?? ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

