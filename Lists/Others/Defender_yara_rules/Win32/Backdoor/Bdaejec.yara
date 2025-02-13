rule Backdoor_Win32_Bdaejec_A_2147679593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bdaejec.A"
        threat_id = "2147679593"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bdaejec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 5c 2e 5c 69 61 53 74 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 66 6f 72 74 6d 70 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 6f 77 6e 4c 6f 61 64 4c 69 73 74 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = {49 44 3d 25 73 26 66 6e 3d 25 73 5f 25 73 26 56 61 72 3d 25 2e 38 58 00}  //weight: 1, accuracy: High
        $x_1_5 = {5a 77 55 6e 6c 6f 61 64 44 72 69 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {81 f9 00 01 00 00 7c d9 33 c9 5f 39 4c 24 0c 76 1d 8b 54 24 08 0f b6 14 11 33 d6 81 e2 ff 00 00 00 c1 ee 08 33 34 90 41 3b 4c 24 0c 72 e3}  //weight: 1, accuracy: High
        $x_1_7 = {51 8b 4d f8 d3 4d fc 59 8b 5d 08 8b 4d fc 33 cb f7 d1 03 cb 03 0a 89 08 8b c2 3b 45 f4 72 be}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

