rule Trojan_Win32_Padvaw_D_2147640015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Padvaw.D"
        threat_id = "2147640015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Padvaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ec 83 c4 fc 60 68 00 10 00 10 64 ff 35 00 00 00 00 64 89 25 00 00 00 00}  //weight: 1, accuracy: High
        $x_2_2 = {76 0e 68 66 06 00 00 6a 13 6a 00 6a 00 ff 55 f0 83 f8 11}  //weight: 2, accuracy: High
        $x_2_3 = {73 65 74 75 70 61 70 69 2e 64 6c 6c 00 43 72 65 61 74 65 50 72 6f 63 65 73 73 4e 6f 74 69 66 79}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

