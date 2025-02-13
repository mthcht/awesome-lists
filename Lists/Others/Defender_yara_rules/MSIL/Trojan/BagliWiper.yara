rule Trojan_MSIL_BagliWiper_A_2147778678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BagliWiper.A"
        threat_id = "2147778678"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BagliWiper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".xlsx" wide //weight: 1
        $x_1_2 = "Bitcoin address:" wide //weight: 1
        $x_1_3 = "Email:" wide //weight: 1
        $x_1_4 = "qdim olunan bitkoin adresin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

