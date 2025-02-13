rule Backdoor_Win32_Mangwam_A_2147660417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mangwam.A"
        threat_id = "2147660417"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mangwam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 69 6e 73 65 74 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 6f 77 6e 65 78 65 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {67 65 74 77 6f 72 6b 2e 70 68 70 3f 6d 61 63 68 69 6e 65 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {6d 61 63 68 69 6e 65 69 64 2e 70 68 70 3f 63 68 65 63 6b 73 74 72 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

