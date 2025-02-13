rule Trojan_Win32_Dhodareet_A_2147696647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dhodareet.A"
        threat_id = "2147696647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dhodareet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 65 c6 06 61 c6 46 01 76 c6 46 02 67 c6 46 03 73 c6 46 04 63 c6 46 05 61 c6 46 06 6e 88 4e 07 c6 46 08 2e 88 46 09}  //weight: 1, accuracy: High
        $x_1_2 = {3d 00 00 ff 7f 77 29 68 e9 00 00 00 53 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 7b 14 80 3f e9 75 7b 8b 4b 18 b8 90 90 90 90}  //weight: 1, accuracy: High
        $x_1_4 = {3d 85 de 23 00 75 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

