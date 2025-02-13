rule TrojanSpy_Win32_Small_DI_2147602510_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Small.DI"
        threat_id = "2147602510"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 6e 64 20 57 65 62 4d 6f 6e 65 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 61 6d 62 6f 74 73 2f 77 2f 43 66 67 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 6f 64 65 64 5f 62 79 5f 4e 6f 63 74 61 6d 62 75 6c 61 61 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {6f 77 3d 6f 70 74 69 6f 6e 73 00 00 77 6d 6b 3a 70 61 79 74 6f 3f 50 75 72 73 65 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

