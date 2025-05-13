rule VirTool_Win64_LokAgnt_B_2147941246_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/LokAgnt.B"
        threat_id = "2147941246"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "LokAgnt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 44 24 48 61 c6 44 24 49 6d c6 44 24 4a 73 c6 44 24 4b 69 c6 44 24 4c 2e c6 44 24 4d 64 c6 44 24 4e 6c c6 44 24 4f 6c c6 44 24 50 00 c6 44 24 78 90 c6 44 24 79 90 c6 44 24 7a 90 c6 44 24 7b b8 c6 44 24 7c 57 c6 44 24 7d 00 c6 44 24 7e 07 c6 44 24 7f 80 c6 84 24 80 00 00 00 c3}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 b8 01 00 00 00 03 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {81 38 50 45 00 00 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

