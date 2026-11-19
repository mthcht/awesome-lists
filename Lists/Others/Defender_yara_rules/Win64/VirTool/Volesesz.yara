rule VirTool_Win64_Volesesz_A_2147982445_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Volesesz.A"
        threat_id = "2147982445"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Volesesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 8d a8 17 00 00 89 4c 24 20 48 8b 8d b0 17 00 00 4c 8b c9 48 8b 8d b8 17 00 00 44 8b c1 48 8b d0 48 8b 4d 78 ff ?? ?? ?? ?? ?? 89 85 d4 00 00 00 83 bd d4 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 8d 48 04 00 00 e8 [0-17] 48 8b c8 ff ?? ?? ?? ?? ?? 48 89 85 68 02 00 00 48 83 bd 68 02 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b8 ff 0f 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 4d 78 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 83 bd 14 11 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

