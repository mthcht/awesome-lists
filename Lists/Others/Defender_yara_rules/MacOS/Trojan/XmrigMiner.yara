rule Trojan_MacOS_XmrigMiner_A_2147788350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XmrigMiner.A"
        threat_id = "2147788350"
        type = "Trojan"
        platform = "MacOS: "
        family = "XmrigMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "./xmrig" wide //weight: 3
        $x_5_2 = "-o stratum+tcp://" wide //weight: 5
        $x_5_3 = "-o stratum+udp://" wide //weight: 5
        $x_2_4 = "-c config.json" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

