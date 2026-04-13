rule VirTool_Win64_Silevesz_A_2147966882_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Silevesz.A"
        threat_id = "2147966882"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Silevesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 c5 e8 ?? ?? ?? ?? 80 38 00 48 89 c3 ?? ?? ?? ?? ?? ?? 4c 89 e9 e8 ?? ?? ?? ?? 80 3b 00 49 89 c5 ?? ?? 66 0f [0-17] 48 89 c2 4c 89 f1 0f 29 4c 24 20 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 54 24 68 0f 29 a4 24 50 01 00 00 0f 29 ac 24 40 01 00 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {31 c9 41 b8 08 00 00 00 ba 10 00 00 00 48 c7 84 24 70 01 00 00 00 00 00 00 e8 ?? ?? ?? ?? 4c 89 e1 c7 84 24 4c 01 00 00 00 00 00 00 48 89 84 24 78 01 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

