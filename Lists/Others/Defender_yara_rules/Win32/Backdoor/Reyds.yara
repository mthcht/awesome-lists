rule Backdoor_Win32_Reyds_A_2147652083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Reyds.A"
        threat_id = "2147652083"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Reyds"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 6c 6a 07 59 33 c0 8d 7d ac f3 ab 6a 0a 66 ab 59 33 c0 68 a0 00 00 00 8d 7d cc 50 f3 ab}  //weight: 1, accuracy: High
        $x_1_2 = {80 3e 00 75 1a 69 d2 04 01 00 00 81 c2}  //weight: 1, accuracy: High
        $x_1_3 = {3c e8 74 04 3c e9 75 08 8b cb}  //weight: 1, accuracy: High
        $x_1_4 = {33 db f3 a6 74 15 83 c2 28 ff 45 fc 66 39 45 fc 72 e4 33 c0}  //weight: 1, accuracy: High
        $x_2_5 = {25 73 3f 69 64 3d 25 73 26 75 69 64 3d 25 73 26 6f 73 3d 25 73 00}  //weight: 2, accuracy: High
        $x_1_6 = "XHFHGEBD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

