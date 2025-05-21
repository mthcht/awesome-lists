rule VirTool_Win64_Sysnull_A_2147941785_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sysnull.A"
        threat_id = "2147941785"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sysnull"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 57 41 56 41 55 41 54 56 57 49 89 cd 49 89 d6 4d 89 c7 4c 89 c9 48 8b 54 24 58 4c 8b 44 24 60 4c 8b 4c 24 68 52 48 c7 c0 08 00 00 00 49 f7 e7 5a 49 89 c4 48 29 c4}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 e7 51 4c 89 f9 f3 48 a5 59 49 89 ca 4c 89 e8 48 83 ec 20 41 ff d6 49 83 c4 20 4c 01 e4 5f 5e 41 5c 41 5d 41 5e 41 5f c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

