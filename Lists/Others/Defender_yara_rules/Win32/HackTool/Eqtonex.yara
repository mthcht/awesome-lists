rule HackTool_Win32_Eqtonex_A_2147767771_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Eqtonex.A!ibt"
        threat_id = "2147767771"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Eqtonex"
        severity = "High"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 69 6e 64 52 65 6e 64 65 7a 76 6f 75 73 00 63 6c 6f 73 65 45 4d}  //weight: 1, accuracy: High
        $x_1_2 = {63 6c 6f 73 65 52 65 6e 64 65 7a 76 6f 75 73 00 63 6f 6e 6e 65 63 74 52 65 6e 64 65 7a 76 6f 75 73}  //weight: 1, accuracy: High
        $x_1_3 = {64 69 73 63 6f 6e 6e 65 63 74 52 65 6e 64 65 7a 76 6f 75 73 00 67 65 74 44 65 66 61 75 6c 74 45 4d 46 69 6c 65}  //weight: 1, accuracy: High
        $x_1_4 = {6f 70 65 6e 45 4d 46 6f 72 57 72 69 74 69 6e 67 00 72 65 61 64 50 61 72 61 6d 73 46 72 6f 6d 45 4d}  //weight: 1, accuracy: High
        $x_1_5 = {72 65 63 76 53 6f 63 6b 65 74 00 73 65 6e 64 53 6f 63 6b 65 74 73 00 77 72 69 74 65 50 61 72 61 6d 73 54 6f 45 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

