rule Trojan_Win64_SilverBasket_B_2147937501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilverBasket.B!dha"
        threat_id = "2147937501"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilverBasket"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 58 00 00 80 00 00 00 10 00 00 00 10 00 00 00 10 00 00 00 e0 00 00 00 e8 03 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5d 58 00 00 80 00 00 00 10 00 00 00 10 00 00 00 10 00 00 00 e0 00 00 00 e8 03 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {f0 55 00 00 80 00 00 00 10 00 00 00 10 00 00 00 10 00 00 00 e0 00 00 00 e8 03 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {65 4a 00 00 80 00 00 00 10 00 00 00 10 00 00 00 10 00 00 00 e0 00 00 00 e8 03 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

