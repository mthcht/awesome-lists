rule Backdoor_Win32_Yohakest_A_2147680413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Yohakest.A"
        threat_id = "2147680413"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Yohakest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 68 61 63 6b 2f 63 6f 6d 6d 61 6e 64 2e 70 68 70 3f 63 6f 6d 70 75 74 65 72 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\yoyo\\docu" ascii //weight: 1
        $x_1_3 = {48 61 63 6b 65 72 20 73 61 79 73 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = {33 36 30 30 00 57 69 6e 64 6f 77 73 20 54 61 73 6b 20 4d 61 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

