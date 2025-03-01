rule Trojan_AndroidOS_OriGami_A_2147837927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/OriGami.A"
        threat_id = "2147837927"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "OriGami"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HuiofcvdQ2FsbA==" ascii //weight: 1
        $x_1_2 = "LIKK Save Error" ascii //weight: 1
        $x_1_3 = "to get this working. Tap on 'Ok' to go to Accessibility Settings" ascii //weight: 1
        $x_1_4 = "Added in call list" ascii //weight: 1
        $x_1_5 = "Eight error in ne stop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

