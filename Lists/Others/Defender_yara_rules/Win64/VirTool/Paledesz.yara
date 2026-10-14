rule VirTool_Win64_Paledesz_A_2147980266_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Paledesz.A"
        threat_id = "2147980266"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Paledesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 31 c9 45 31 c0 31 c9 48 89 54 24 48 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 54 24 40 48 89 f2 48 89 44 24 38 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 08 c7 44 24 20 01 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 8c 24 00 01 00 00 ff [0-19] 85 c0 ?? ?? ?? ?? ?? ?? 48 89 f2 b9 04 01 00 00 ff ?? ?? ?? ?? ?? 48 89 f1}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 5c 24 70 48 8b b4 24 80 00 00 00 [0-33] 48 89 ac 24 30 01 00 00 4c 89 a4 24 40 01 00 00 48 89 5c 24 70 48 89 b4 24 80 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

