rule Virus_Win32_Lobaost_A_2147665273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Lobaost.A"
        threat_id = "2147665273"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Lobaost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 76 63 68 6f 73 74 2e 65 78 65 00 ff ff ff ff 05 00 00 00 73 68 61 72 61 00 00 00 ff ff ff ff 0b 00 00 00 6c 6f 61 64 5f 6d 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {73 63 20 64 65 6c 65 74 65 20 41 6e 74 69 56 69 72 57 65 62 53 65 72 76 69 63 65 00 73 63 20 64 65 6c 65 74 65 20 41 6e 74 69 56 69 72 53 65 72 76 69 63 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 10 27 00 00 e8 12 5b fe ff e8 05 e6 ff ff e8 98 fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

