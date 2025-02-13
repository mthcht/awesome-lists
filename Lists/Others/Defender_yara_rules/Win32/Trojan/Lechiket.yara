rule Trojan_Win32_Lechiket_A_2147657355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lechiket.A"
        threat_id = "2147657355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lechiket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET /%s?&id=%s&mark=%s" ascii //weight: 1
        $x_1_2 = {6c 65 74 63 68 69 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {5b 4e 45 54 57 4f 52 4b 20 44 41 54 41 3a 5d 00}  //weight: 1, accuracy: High
        $x_1_4 = {6e 5f 37 5f 33 32 00}  //weight: 1, accuracy: High
        $x_2_5 = {8b 45 0c 33 c3 33 d2 6a 19 59 f7 f1 8b 45 08 01 7d 0c 80 c2 61 88 14 06 46 83 fe 08 72 e2 8b f8 4f f6 c3 01 c6 04 06 00 74 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

