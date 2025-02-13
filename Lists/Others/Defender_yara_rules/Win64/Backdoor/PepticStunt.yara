rule Backdoor_Win64_PepticStunt_B_2147904114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/PepticStunt.B!dha"
        threat_id = "2147904114"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "PepticStunt"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 fb 07 0f 85 2e 02 00 00 41 81 39 65 78 65 63 0f 85 06 01 00 00 66 41 81 79 04 75 74 0f 85 f9 00 00 00 41 80 79 06 65 0f 85 ee 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 83 fb 08 0f 85 48 02 00 00 49 ba 73 65 6e 64 66 69 6c 65}  //weight: 1, accuracy: High
        $x_1_3 = {41 81 39 67 65 74 66 0f 85 60 03 00 00 66 41 81 79 04 69 6c 0f 85 53 03 00 00 41 80 79 06 65 0f 85 48 03 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

