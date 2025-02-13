rule Backdoor_Win32_Grifwin_A_2147627314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Grifwin.A"
        threat_id = "2147627314"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Grifwin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 25 73 5c 25 73 2e 65 78 65 00 00 57 69 6e 67 72 66 6d 4d 75 74 65 78 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 44 52 5f 41 47 45 4e 54 49 44 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 6f 77 4c 65 76 65 6c 4d 6f 75 73 65 50 72 6f 63 00 00 00 4c 6f 77 4c 65 76 65 6c 4b 65 79 62 6f 61 72 64 50 72 6f 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

