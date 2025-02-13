rule Trojan_Linux_LockBitRansom_A_2147931677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/LockBitRansom.A"
        threat_id = "2147931677"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "LockBitRansom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "encrypt" wide //weight: 10
        $x_1_2 = "-extensions lockbit" wide //weight: 1
        $x_1_3 = "-extensions ryuk" wide //weight: 1
        $x_1_4 = "-extensions enc" wide //weight: 1
        $x_10_5 = "-startpath" wide //weight: 10
        $x_10_6 = "-publickey" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_LockBitRansom_B_2147931678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/LockBitRansom.B"
        threat_id = "2147931678"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "LockBitRansom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "simulate" wide //weight: 10
        $x_1_2 = "-extensions lockbit" wide //weight: 1
        $x_1_3 = "-extensions ryuk" wide //weight: 1
        $x_1_4 = "-extensions enc" wide //weight: 1
        $x_10_5 = "-publickey" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

