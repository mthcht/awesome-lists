rule Backdoor_Win32_DizzyMarkhor_C_2147973293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DizzyMarkhor.C!dha"
        threat_id = "2147973293"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DizzyMarkhor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 53 00 63 00 72 00 65 00 65 00 6e 00 43 00 61 00 70 00 2e 00 70 00 6e 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 6d 00 6f 00 64 00 65 00 3d 00 72 00 65 00 73 00 75 00 6c 00 74 00 26 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 67 00 65 00 74 00 75 00 73 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 6d 00 6f 00 64 00 65 00 3d 00 69 00 6e 00 66 00 6f 00 26 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 4c 00 53 00 6c 00 69 00 73 00 74 00 7b 00 2d 00 66 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 53 00 63 00 72 00 65 00 65 00 6e 00 43 00 61 00 70 00 2e 00 62 00 6d 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

