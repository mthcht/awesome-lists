rule Trojan_AndroidOS_Smstheif_N_2147888218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smstheif.N"
        threat_id = "2147888218"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smstheif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cers9ijYTmsas2mLAdsssss" ascii //weight: 1
        $x_1_2 = "udalsnbrFddZdsisqp" ascii //weight: 1
        $x_1_3 = "sfmmbuqkhbtqheh" ascii //weight: 1
        $x_1_4 = "tamskwtwodewik" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

