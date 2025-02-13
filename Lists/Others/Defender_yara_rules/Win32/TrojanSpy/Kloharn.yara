rule TrojanSpy_Win32_Kloharn_A_2147646123_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Kloharn.A"
        threat_id = "2147646123"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kloharn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 00 52 00 61 00 4e 00 48 00 61 00 43 00 4b 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 61 00 6c 00 61 00 6d 00 21 00 70 00 6c 00 7a 00 2d 00 63 00 6c 00 6f 00 73 00 65 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {64 00 3a 00 5c 00 6c 00 6f 00 67 00 5c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 00 74 00 74 00 72 00 69 00 62 00 20 00 64 00 3a 00 5c 00 6c 00 6f 00 67 00 20 00 2b 00 68 00 20 00 2b 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

