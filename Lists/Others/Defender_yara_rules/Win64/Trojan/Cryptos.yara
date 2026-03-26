rule Trojan_Win64_Cryptos_AMTB_2147965676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cryptos!AMTB"
        threat_id = "2147965676"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {28 13 00 00 06 7e 04 00 00 04 7e 05 00 00 04 28 09 00 00 06 2a}  //weight: 6, accuracy: High
        $x_2_2 = {2a 00 28 08 00 00 06 28 02 00 00 0a 6f 03 00 00 0a 13 00 38 a4 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 01 00 fe 0c 01 00}  //weight: 2, accuracy: High
        $x_2_3 = {38 42 05 00 00 20 00 00 00 00 fe 0e 02 00 fe 0c 02 00 45 04 00 00 00 4c 00 00 00 98 00 00 00 5e 00 00 00 49 00 00 00 fe 0c 02 00 20 0b 00 00 00 3b 29 05 00 00 fe 0c 02 00 20 df 03 00 00 3b cb ff ff ff 38 77 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {11 02 72 01 00 00 70 20 00 01 00 00 14 14 14 6f 04 00 00 0a 26 38 00 00 00 00 dd 67 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

