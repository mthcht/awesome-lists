rule Trojan_Win64_Dohdoor_AMTB_2147965081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dohdoor!AMTB"
        threat_id = "2147965081"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dohdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {41 8b 09 41 8b 51 08 49 03 ce 41 8b 79 04 49 03 d7 48 83 ff 08 72 2d 44 8b c7 49 c1 e8 03 49 6b c0 f8 48 03 f8 66 66 66 0f 1f 84 00 00 00 00 00}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

