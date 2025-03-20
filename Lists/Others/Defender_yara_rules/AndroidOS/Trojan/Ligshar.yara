rule Trojan_AndroidOS_Ligshar_A_2147936550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ligshar.A"
        threat_id = "2147936550"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ligshar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ConfigFailDays1" ascii //weight: 2
        $x_2_2 = "RecordFailTimes1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

