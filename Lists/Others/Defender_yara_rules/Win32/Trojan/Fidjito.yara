rule Trojan_Win32_Fidjito_A_2147649832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fidjito.A"
        threat_id = "2147649832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fidjito"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 37 8d 44 24 14 6a 00 50 57 53 56}  //weight: 1, accuracy: High
        $x_1_2 = {b3 6c 52 c6 44 24 20 73 c6 44 24 21 66 c6 44 24 22 63}  //weight: 1, accuracy: High
        $x_1_3 = {8d 44 24 0c 50 6a 04 56 6a 09 53 c7 06 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

