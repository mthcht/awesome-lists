rule VirTool_Win64_Aethesz_A_2147962168_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Aethesz.A"
        threat_id = "2147962168"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Aethesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 e1 e8 ?? ?? ?? ?? 89 c1 48 69 c9 ?? ?? ?? ?? 48 c1 e9 27 69 c9 d0 07 00 00 f7 d9 ?? ?? ?? 81 c2 d0 07 00 00 31 c9 ff ?? ?? ?? ?? ?? 48 8b 95 80 1c 00 00 48 85 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 80 1d 00 00 c6 00 02 48 c7 85 88 1d 00 00 01 00 00 00 48 8b 85 78 1d 00 00 48 ff c8 ba 01 00 00 00 48 83 f8 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

