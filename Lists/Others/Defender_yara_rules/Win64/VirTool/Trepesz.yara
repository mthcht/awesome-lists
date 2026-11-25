rule VirTool_Win64_Trepesz_A_2147982772_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Trepesz.A"
        threat_id = "2147982772"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Trepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 20 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 9c 24 80 00 00 00 41 b8 03 00 00 00 ?? ?? ?? ?? ?? ?? ?? 33 c9 e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {45 33 c9 48 89 44 24 68 ?? ?? ?? ?? ?? 48 89 7c 24 74 ba 01 00 00 00 89 7c 24 7c 33 c9 48 89 5c 24 48 c7 44 24 5c 01 00 00 00 c7 44 24 70 01 02 01 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 7c 24 30 45 33 c9 c7 44 24 28 80 00 00 00 ba 00 00 00 40 41 b8 01 00 00 00 c7 44 24 20 02 00 00 00 ff ?? ?? ?? ?? ?? 48 8b d8 48 83 f8 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

