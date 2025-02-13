rule Trojan_Win32_Nefyn_A_2147682073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nefyn.A"
        threat_id = "2147682073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nefyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 00 73 00 75 00 00 00 25 00 74 00 65 00 6d 00 70 00 25 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 10 46 c6 44 24 11 55 c6 44 24 12 43 c6 44 24 13 4b c6 44 24 14 54 c6 44 24 15 58}  //weight: 1, accuracy: High
        $x_1_3 = {f3 a5 b9 33 00 00 00 8d bc 24 4c 03 00 00 f3 ab b9 41 00 00 00 8d bc 24 10 02 00 00 f3 ab b9 41 00 00 00 8d bc 24 0c 01 00 00 f3 ab b9 41 00 00 00 8d 7c 24 08 f3 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

