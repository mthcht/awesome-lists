rule Backdoor_Win32_Stokief_A_2147654386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stokief.A"
        threat_id = "2147654386"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stokief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7f 43 8b 45 9c 03 85 74 ff ff ff 80 38 23 75 11 8d 45 f8 03 85 74 ff ff ff 83 c0 80 c6 00 00}  //weight: 1, accuracy: High
        $x_2_2 = {77 6d 5f 68 6f 6f 6b 73 2e 64 6c 6c 00 6c 6f 67 6d 65 73 73 61 67 65 73 2e 64 6c 6c 00 75 70 66 74 70 00 76 6e 63 69 6e 69}  //weight: 2, accuracy: High
        $x_1_3 = {2f 70 75 62 6c 69 63 5f 68 74 6d 6c 2f 6b 6c 6f 67 2f 25 73 2f 00 6b 65 79 6c 6f 67 2e 6c 6f 67}  //weight: 1, accuracy: High
        $x_1_4 = "infectando disco local..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

