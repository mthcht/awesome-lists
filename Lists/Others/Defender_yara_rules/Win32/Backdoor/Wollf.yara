rule Backdoor_Win32_Wollf_A_2147609034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wollf.gen!A"
        threat_id = "2147609034"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wollf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 4f 50 4d 53 47 20 3c 4d 65 73 73 61 67 65 3e 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 49 4c 4c 20 3c 50 72 6f 63 65 73 73 5f 49 44 3e 00}  //weight: 1, accuracy: High
        $x_1_3 = {46 50 55 54 20 3c 4c 6f 63 61 6c 5f 66 69 6c 65 3b 52 65 6d 6f 74 65 5f 66 69 6c 65 5b 3b 55 73 65 72 3b 50 61 73 73 5d 3e 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 59 53 49 4e 46 4f 00}  //weight: 1, accuracy: High
        $x_1_5 = {66 70 75 74 00 00 00 00 66 67 65 74 00 00 00 00 77 67 65 74 00 00 00 00}  //weight: 1, accuracy: High
        $x_3_6 = {56 8b 74 24 08 85 f6 7f 04 33 c0 5e c3 8b 54 24 0c 57 8b fa 83 c9 ff 33 c0 6a 00 f2 ae f7 d1 49 51 52 56}  //weight: 3, accuracy: High
        $x_5_7 = {be be 1d 00 00 53 (6a ??|68 ?? ?? ?? ??) 8d 44 24 ?? 56 50 e8 ?? ?? ?? ?? (8b e8|89 c5) 83 c4 10 (3b eb|39 dd) 7f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

