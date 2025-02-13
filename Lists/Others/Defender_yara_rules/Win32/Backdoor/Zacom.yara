rule Backdoor_Win32_Zacom_A_2147681818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zacom.A"
        threat_id = "2147681818"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zacom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 45 e0 2b 85 cc d6 ff ff 89 45 e4 3d 40 77 1b 00 0f 83 e2 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {2e 61 73 70 3f 48 6f 73 74 49 44 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 6f 6f 67 6c 65 5a 43 4d 00}  //weight: 1, accuracy: High
        $x_1_4 = {47 41 50 5a 43 4d 5f 4d 41 49 4e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 54 54 69 70 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 49 53 00 47 45 54 00 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_7 = {3d 04 10 00 00 77 23 74 1a 2d 04 0c 00 00 74 0c 83 e8 05 75 23 bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zacom_C_2147706723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zacom.C"
        threat_id = "2147706723"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zacom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c6 47 04 4d c6 47 05 5a c6 47 06 90 c6 47 07 00}  //weight: 5, accuracy: High
        $x_1_2 = {2e 61 73 70 3f 48 6f 73 74 49 44 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 54 54 69 70 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_4 = "www.microsoft.com" ascii //weight: 1
        $x_1_5 = "reg add hkcu\\software\\microsoft\\windows\\currentversion\\run /v" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

