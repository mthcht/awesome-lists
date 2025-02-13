rule PWS_Win32_Tendcef_A_2147619585_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tendcef.A"
        threat_id = "2147619585"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tendcef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3f 00 76 00 61 00 72 00 65 00 61 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {76 00 70 00 61 00 73 00 73 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 5c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 4e 46 70 61 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

