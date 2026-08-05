rule VirTool_Win64_Lepesz_A_2147975261_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Lepesz.A"
        threat_id = "2147975261"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Lepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 7c 24 68 ff [0-16] ba 2a 00 00 00 48 8b c8 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ff ?? ?? ?? ?? ?? 8b d0 ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 4c 24 68 ?? ?? ?? ?? ?? 48 89 44 24 28 41 b9 02 00 00 00 45 33 c0 c7 44 24 20 01 00 00 00 ba ff 01 0f 00 48 89 7c 24 60 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 01 00 00 00 48 89 44 24 38 ?? ?? ?? ?? ?? ?? ?? 48 8b 44 24 78 48 89 74 24 30 48 89 44 24 28 c7 44 24 20 10 04 00 00 ff ?? ?? ?? ?? ?? 8b d8 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

