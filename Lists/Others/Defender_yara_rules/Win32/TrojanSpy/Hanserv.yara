rule TrojanSpy_Win32_Hanserv_A_2147659388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hanserv.A"
        threat_id = "2147659388"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hanserv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {50 63 4d 79 57 72 6b 31 31 30 00 00 43 4d 61 69 6c 43 6f 6d 44 6f 63 00 43 4d 61 69 6c 43 6f 6d 56 69 65 77 00}  //weight: 3, accuracy: High
        $x_1_2 = {2f 75 6e 00 73 71 6c 73 65 72 76 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 52 75 6e 00 00 00 64 75 72 6c}  //weight: 1, accuracy: High
        $x_1_4 = {73 71 6c 75 70 64 61 74 65 2e 65 78 65 00 00 00 76 65 72}  //weight: 1, accuracy: High
        $x_1_5 = {47 42 00 63 3a 5c 00 50 72 6f 63 65 73 73 6f 72 4e 61 6d 65 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {66 65 66 64 61 73 66 64 61 73 66 64 61 71 2e 68 61 6e 6d 61 69 6c 2e 6e 65 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

