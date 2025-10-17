rule VirTool_Win64_Wfdmp_A_2147955393_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Wfdmp.A"
        threat_id = "2147955393"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Wfdmp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 75 d7 ff ?? ?? ?? ?? ?? 48 8b c8 ?? ?? ?? ?? ba 28 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {45 33 c0 ba 00 00 00 40 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 4c 8b f0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 5c 24 30 48 89 5c 24 28 48 c7 44 24 20 04 00 00 00 ?? ?? ?? ?? 33 d2 41 b8 0b 00 02 00 48 8b cf ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

