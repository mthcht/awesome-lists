rule Backdoor_Win32_Hackdrt_A_2147633886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hackdrt.A"
        threat_id = "2147633886"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hackdrt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 53 00 2d 00 44 00 52 00 54 00 20 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 00 53 00 2d 00 44 00 52 00 54 00 20 00 32 00 2e 00 32 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 54 00 72 00 6f 00 6a 00 61 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {55 00 20 00 64 00 69 00 73 00 6b 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 52 00 4f 00 4f 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {75 70 64 61 74 65 5c 48 6c 4d 61 69 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {49 44 4f 72 50 41 53 53 09 57 72 6f 6e 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {4f 00 70 00 65 00 6e 00 33 00 33 00 38 00 39 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {44 00 65 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 74 00 68 00 65 00 20 00 68 00 61 00 72 00 64 00 20 00 64 00 69 00 73 00 6b 00 28 00 26 00 44 00 29 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 52 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 28 00 26 00 44 00 29 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {56 00 6f 00 69 00 63 00 65 00 20 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 28 00 26 00 57 00 29 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

