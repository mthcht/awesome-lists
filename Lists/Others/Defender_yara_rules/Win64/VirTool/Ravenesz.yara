rule VirTool_Win64_Ravenesz_A_2147963655_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Ravenesz.A"
        threat_id = "2147963655"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Ravenesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 08 00 00 00 e8 [0-17] 48 89 45 a0 48 c7 45 a8 07 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 45 b0 48 c7 45 b8 03 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 45 c0 48 c7 45 c8 09 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {41 c6 84 24 48 01 00 00 00 48 89 bd 20 07 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 85 28 07 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 85 c8 03 00 00 48 f7 d8 [0-19] ba 0b 00 00 00 e8 ?? ?? ?? ?? 49 89 c5 4c 8b bd b0 03 00 00 4d 85 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

