rule Trojan_Win32_Clucsplic_A_2147599149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clucsplic.A"
        threat_id = "2147599149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clucsplic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4e 74 43 72 65 61 74 65 54 68 72 65 61 64 00 00 57 61 72 6e 69 6e 67 3a 20 43 6f 6d 70 6f 6e 65}  //weight: 5, accuracy: High
        $x_1_2 = "\\\\.\\Global" ascii //weight: 1
        $x_5_3 = {8d 45 e4 50 8d 4d fc 51 6a 00 6a 00 6a 0c 8d 55 d8 52 68 00 e0 22 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

