rule Backdoor_Win32_Mipakwin_A_2147685663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mipakwin.A"
        threat_id = "2147685663"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mipakwin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 00 65 00 66 00 72 00 65 00 73 00 68 00 53 00 49 00 4e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 00 44 00 53 00 70 00 61 00 63 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 65 00 6e 00 64 00 46 00 69 00 6c 00 65 00 73 00 54 00 6f 00 54 00 72 00 61 00 73 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 00 61 00 73 00 74 00 4d 00 75 00 6c 00 74 00 69 00 56 00 4d 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 00 75 00 74 00 4d 00 75 00 6c 00 74 00 69 00 46 00 69 00 6c 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {4d 00 6b 00 65 00 44 00 69 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {55 00 6e 00 53 00 68 00 61 00 72 00 65 00 4d 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {4b 00 69 00 6c 00 6c 00 53 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {52 00 67 00 42 00 72 00 6f 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {4b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {50 00 43 00 2d 00 63 00 69 00 6c 00 6c 00 69 00 6e 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

