rule VirTool_Win64_Vehelz_A_2147961074_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Vehelz.A"
        threat_id = "2147961074"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Vehelz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 45 d0 48 c7 45 d8 01 00 00 00 48 c7 45 e0 08 00 00 00 0f 57 c0 0f 11 45 e8 ?? ?? ?? ?? e8 [0-17] 48 89 46 48 80 4e 70 01 48 ff 86 f8 00 00 00 81 4e 30 10 00 10 00 ?? ?? f6 46 68 01}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 46 78 00 00 00 00 48 8b 86 98 00 00 00 48 8b 08 48 89 8e f8 00 00 00 48 83 c0 08 48 89 86 98 00 00 00 48 c7 46 68 00 00 00 00 b8 ff ff ff ff 48 83 c4 58 5e 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

