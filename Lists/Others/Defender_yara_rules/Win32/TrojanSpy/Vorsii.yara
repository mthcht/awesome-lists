rule TrojanSpy_Win32_Vorsii_A_2147684621_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Vorsii.A"
        threat_id = "2147684621"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Vorsii"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {69 73 6e 5f 72 65 6c 6f 61 64 63 6f 6e 66 69 67 00}  //weight: 2, accuracy: High
        $x_2_2 = {69 73 6e 5f 67 65 74 6c 6f 67 00}  //weight: 2, accuracy: High
        $x_2_3 = {69 73 6e 5f 6c 6f 67 70 61 74 68 00}  //weight: 2, accuracy: High
        $x_2_4 = {69 73 6e 5f 6c 6f 67 64 65 6c 00}  //weight: 2, accuracy: High
        $x_1_5 = {5c 69 73 6e 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 69 73 6e 37 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

