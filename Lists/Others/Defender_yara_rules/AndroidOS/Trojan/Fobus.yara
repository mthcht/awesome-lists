rule Trojan_AndroidOS_Fobus_A_2147896290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fobus.A"
        threat_id = "2147896290"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fobus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Uleb128ToInt" ascii //weight: 1
        $x_1_2 = "addZipToDex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

