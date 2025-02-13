rule Trojan_Win32_Serkdes_A_2147679666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Serkdes.A"
        threat_id = "2147679666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Serkdes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 79 70 77 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = "0(encrypt) or 1(decrypt)" ascii //weight: 1
        $x_1_3 = {8b 9c 96 00 03 00 00 8a 51 ff 0b fb 49 8b d8 83 e2 3f 83 e3 3f 33 d3 c1 f8 04 8b 9c 96 00 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

