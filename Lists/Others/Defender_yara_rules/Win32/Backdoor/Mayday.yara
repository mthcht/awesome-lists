rule Backdoor_Win32_Mayday_A_2147605124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mayday.gen!A"
        threat_id = "2147605124"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mayday"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 30 30 31 30 30 30 31 00 00 00 00 2e 65 78 65 00 00 00 00 77 6d 75 70 64 61 74 65 00 00 00 00 73 76 63 68 6f 73 74 00 34 2e 30 00}  //weight: 1, accuracy: High
        $x_1_2 = {45 6e 61 62 6c 65 64 00 44 69 73 61 62 6c 65 64 00 00 00 00 3a 2a 3a 00 00 00 00 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f}  //weight: 1, accuracy: High
        $x_1_3 = {45 63 68 6f 52 65 71 75 65 73 74 00 53 59 53 54}  //weight: 1, accuracy: High
        $x_1_4 = {4d 73 67 00 4c 69 73 74 00 00 00 00 4d 61 69 6c 00 00 00 00 67 75 69 64 00 00 00 00 66 69 6c 65 6e 61 6d 65 00 00 00 00 63 6f 6d 6d 61 6e 64 00 70 61 73 73 77 6f 72 64 00 00 00 00 64 6f 77 6e}  //weight: 1, accuracy: High
        $x_1_5 = {75 70 64 61 74 65 00 00 6c 65 61 72 6e 00 00 00 6c 6f 67 00 67 65 74 6e 61 6d 65 00 6d 61 69 6c 73 74 61 74 2e 6c 6f 67 00 00 00 00 25 30 31 30}  //weight: 1, accuracy: High
        $x_1_6 = {7c 25 30 31 30 75 00 00 00 2e 63 6f 6d 00 00 00 00 2e 65 6d 6c 00 00 00 00 30 30 30 30 30 30 30}  //weight: 1, accuracy: High
        $x_1_7 = {57 4f 49 2e 62 69 7a 00 57 4c 42 2e 69 6e 66 6f}  //weight: 1, accuracy: High
        $x_1_8 = {49 6e 63 72 65 64 69 62 6c 65 44 61 74 65 73 2e 63 6f 6d 00 49 64 65 61 6c 4c 6f 76 65 72 2e 63}  //weight: 1, accuracy: High
        $x_1_9 = {53 65 6d 69 63 6f 6e 64 75 63 74 6f 72 73 2e 62 69 7a 00 00 53 63 65 6e 74 65 64 2e 62 69 7a}  //weight: 1, accuracy: High
        $x_1_10 = "A1445E6F635CD9CEB84E100D800699990D017C432D3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

