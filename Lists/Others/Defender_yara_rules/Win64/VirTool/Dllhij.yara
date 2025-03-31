rule VirTool_Win64_Dllhij_A_2147937398_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dllhij.A"
        threat_id = "2147937398"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dllhij"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 68 01 00 00 00 48 b8 34 12 6f 5e 4d 3c 2b 1a ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {56 57 48 89 c7 48 81 c6 c2 05 00 00 48 b9 12 00 00 00 00 00 00 00 f3 a4 5f 5e 4c 89 68 08 48 31 c9 66 41 8b 0f 48 8b 45 10 48 29 c8 49 89 c4 49 89 cd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

