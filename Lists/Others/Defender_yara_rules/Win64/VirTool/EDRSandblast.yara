rule VirTool_Win64_EDRSandblast_D_2147835847_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/EDRSandblast.D"
        threat_id = "2147835847"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "EDRSandblast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 04 b8 c6 45 05 42 c6 45 06 42 c6 45 07 42 c6 45 08 42 c6 45 24 4c c6 45 25 8b c6 45 26 d1 c6 45 44 0f c6 45 45 05 c6 45 46 c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 c7 45 68 0b 00 00 00 41 b9 04 00 00 00 41 b8 00 30 00 00 48 8b 55 68 33 c9 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 4c 8b d1 0f 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

