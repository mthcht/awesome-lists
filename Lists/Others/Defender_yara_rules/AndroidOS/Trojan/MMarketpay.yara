rule Trojan_AndroidOS_MMarketpay_A_2147896814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/MMarketpay.A"
        threat_id = "2147896814"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "MMarketpay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "consurm url" ascii //weight: 2
        $x_2_2 = "validation submitUrl:" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

