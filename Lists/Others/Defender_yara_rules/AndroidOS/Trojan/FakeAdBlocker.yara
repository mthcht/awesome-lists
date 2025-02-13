rule Trojan_AndroidOS_FakeAdBlocker_A_2147788907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeAdBlocker.A"
        threat_id = "2147788907"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeAdBlocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Lcom/cold/toothbrush/ctrl;" ascii //weight: 5
        $x_5_2 = "/svc;" ascii //weight: 5
        $x_5_3 = "/cold/toothbrush/bur" ascii //weight: 5
        $x_5_4 = "/DecryptString;" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

