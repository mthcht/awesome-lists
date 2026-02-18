rule VirTool_Win64_Mowelesz_A_2147963240_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Mowelesz.A"
        threat_id = "2147963240"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mowelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 41 53 41 52 41 51 41 50 51 41 ff 73 28 52 41 ff 73 20 48 83 ec 28 41 ff 73 30 48 83 ec 28 41 ff 73 30 41 ff 73 10}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 84 24 20 05 00 00 c6 84 24 a8 00 00 00 4d c6 84 24 a9 00 00 00 79 c6 84 24 aa 00 00 00 54 c6 84 24 ab 00 00 00 65 c6 84 24 ac 00 00 00 73 c6 84 24 ad 00 00 00 74 c6 84 24 ae 00 00 00 31 c6 84 24 af}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

