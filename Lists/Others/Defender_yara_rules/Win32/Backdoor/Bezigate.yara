rule Backdoor_Win32_Bezigate_B_2147677752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bezigate.B"
        threat_id = "2147677752"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bezigate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 83 fa 32 75 07 b8 01 00 00 80 eb 1f 66 83 fa 33 75 07 b8 02 00 00 80 eb 12 66 83 fa 34}  //weight: 2, accuracy: High
        $x_1_2 = {4d 00 55 00 54 00 58 00 5f 00 42 00 4f 00 5a 00 4f 00 4b 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "%sdfile%i.exe" wide //weight: 1
        $x_1_4 = {00 00 70 00 6c 00 75 00 67 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bezigate_B_2147677752_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bezigate.B"
        threat_id = "2147677752"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bezigate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {03 04 24 13 54 24 04 83 c4 08 8a 00 30 06 46 4b 41 3b cf 7e 02 33 c9 85 db 75 da}  //weight: 3, accuracy: High
        $x_1_2 = {4d 00 55 00 54 00 58 00 5f 00 42 00 4f 00 5a 00 4f 00 4b 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 00 73 00 73 00 65 00 72 00 76 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 00 6f 00 7a 00 70 00 6c 00 75 00 67 00 69 00 6e 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "%s|%s|%s|%s|%d|%s|%d|%d|%s" wide //weight: 1
        $x_1_6 = {53 74 61 72 74 56 4e 43 00}  //weight: 1, accuracy: High
        $x_1_7 = {47 65 74 4b 65 79 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_8 = {53 74 61 72 74 57 65 62 63 61 6d 00}  //weight: 1, accuracy: High
        $x_1_9 = {44 65 6c 65 74 65 4b 65 79 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_10 = {53 65 6e 64 43 61 6d 4c 69 73 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {6d 00 79 00 70 00 61 00 73 00 73 00 00 00 00 00 70 00 6c 00 75 00 67 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

