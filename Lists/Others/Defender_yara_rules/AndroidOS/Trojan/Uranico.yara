rule Trojan_AndroidOS_Uranico_A_2147668297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Uranico.A"
        threat_id = "2147668297"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Uranico"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "uranai/Answer$" ascii //weight: 5
        $x_1_2 = "configChanges" ascii //weight: 1
        $x_1_3 = "geo:0,0?q=donuts" ascii //weight: 1
        $x_1_4 = "REFELER_REQUEST_NAME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

