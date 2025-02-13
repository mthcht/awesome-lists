rule Worm_Win32_Mirkspot_A_2147647973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mirkspot.A"
        threat_id = "2147647973"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mirkspot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 65 00 72 00 65 00 67 00 61 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 00 69 00 6d 00 6d 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 6e 00 74 00 73 00 79 00 73 00 6e 00 74 00 66 00 73 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 00 79 00 73 00 74 00 65 00 6d 00 73 00 66 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {64 00 65 00 73 00 63 00 74 00 6f 00 70 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {72 00 69 00 6d 00 6d 00 61 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {4d 00 75 00 73 00 69 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 20 00 6b 00 69 00 6e 00 6f 00 20 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {61 75 67 75 73 74 6f 2e 74 75 72 69 73 74 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

