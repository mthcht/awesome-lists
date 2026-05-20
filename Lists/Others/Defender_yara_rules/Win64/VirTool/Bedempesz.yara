rule VirTool_Win64_Bedempesz_A_2147969785_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bedempesz.A"
        threat_id = "2147969785"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bedempesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c6 48 c7 85 d0 01 00 00 00 00 00 00 48 8b 95 c0 00 00 00 4c 8b 8d d8 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 20 48 89 d9 49 89 f0 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b9 30 00 00 00 48 89 d9 48 89 fa ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 48 89 bd 48 07 00 00 81 bd e0 00 00 00 00 10 00 00 48 8b bd d8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 89 ad 00 02 00 00 48 c7 85 08 02 00 00 02 00 00 00 c6 85 97 07 00 00 01 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 44 8b 06 b9 10 04 00 00 31 d2 ff ?? ?? ?? ?? ?? 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

