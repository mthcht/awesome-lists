rule PWS_Win32_GinaPass_A_2147705489_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/GinaPass.A!dha"
        threat_id = "2147705489"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "GinaPass"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 22 00 25 00 73 00 22 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 00 73 00 65 00 72 00 53 00 63 00 72 00 69 00 70 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 00 79 00 73 00 74 00 65 00 6d 00 53 00 63 00 72 00 69 00 70 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 00 65 00 65 00 64 00 43 00 74 00 72 00 6c 00 41 00 6c 00 74 00 44 00 65 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 5c 00 53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

