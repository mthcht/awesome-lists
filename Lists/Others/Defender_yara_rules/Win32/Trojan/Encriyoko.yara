rule Trojan_Win32_Encriyoko_A_2147663603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Encriyoko.A"
        threat_id = "2147663603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Encriyoko"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 53 45 4e 4b 41 4b 55 5f 49 53 43 48 49 4e 41 5d 5d 5d 00}  //weight: 1, accuracy: High
        $x_1_2 = {6b 72 65 63 79 63 6c 65 00 00 00 00 72 61 76 62 69 6e}  //weight: 1, accuracy: High
        $x_1_3 = {5c 76 78 73 75 72 2e 62 69 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {6e 65 70 69 61 2e 64 75 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

