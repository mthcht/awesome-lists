rule VirTool_Win64_Bymetesz_A_2147964050_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bymetesz.A"
        threat_id = "2147964050"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bymetesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 53 48 83 ec 70 48 8b ?? ?? ?? ?? ?? 48 33 c4 48 89 44 24 68 ba 00 10 00 00 33 c9 41 b9 40 00 00 00 41 b8 00 30 00 00 ff [0-16] 48 c7 44 24 28 0e 00 00 00 48 89 44 24 30 [0-18] 48 89 44 24 20 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 bc 24 80 00 00 00 [0-18] 81 7c 24 58 00 10 00 00 ?? ?? 81 7c 24 60 00 00 02 00 ?? ?? f6 44 24 5c f0 ?? ?? ?? ?? ?? ?? ?? 48 89 7c 24 20 ?? ?? ?? ?? ?? 48 c7 44 24 28 0b 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

