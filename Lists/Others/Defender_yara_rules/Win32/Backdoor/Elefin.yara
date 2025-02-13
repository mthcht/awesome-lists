rule Backdoor_Win32_Elefin_A_2147656517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Elefin.A"
        threat_id = "2147656517"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Elefin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 00 00 00 00 6c 00 6f 00 61 00 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {4e 74 43 6c 6f 73 65 53 74 61 74 75 73 00 4e 74 4f 70 65 6e 53 74 61 74 75 73}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 77 00 69 00 6e 00 75 00 61 00 64 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 5c 00 77 00 69 00 6e 00 75 00 61 00 64 00 36 00 34 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

