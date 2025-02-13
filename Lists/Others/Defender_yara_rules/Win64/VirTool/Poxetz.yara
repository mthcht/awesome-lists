rule VirTool_Win64_Poxetz_A_2147844668_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Poxetz.A!MTB"
        threat_id = "2147844668"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Poxetz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 41 ff ?? 48 8b 45 a8 48 8b 55 f0 48 89 c1 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 45 a8 00 00 00 00 48 8d 55 b0 48 8d 45 a8 4c 8b 55 f8 41 b9 00 00 00 00 49 89 d0}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 d3 48 8b 03 48 8b 4b 08 48 8b 53 10 4d 31 c0 4c 8b 4b 18 4c 8b 53 20 4c 89 54 24 30 41 ba 00 30 00 00 4c 89 54 24 28 ff}  //weight: 1, accuracy: High
        $x_1_4 = {ba 00 10 00 00 48 c7 c1 ff ff ff ff 48 8b 05 5c 89 00 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

