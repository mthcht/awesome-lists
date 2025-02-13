rule Trojan_Linux_Capfetox_A_2147808034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Capfetox.A"
        threat_id = "2147808034"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Capfetox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "ping" wide //weight: 5
        $x_5_2 = {64 00 6e 00 73 00 2e 00 [0-8] 2e 00 65 00 75 00 2e 00 6f 00 72 00 67 00}  //weight: 5, accuracy: Low
        $x_10_3 = "am5kaSB8IGJhc2g=" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

