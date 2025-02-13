rule Trojan_AndroidOS_Mantis_A_2147827950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mantis.A"
        threat_id = "2147827950"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mantis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ojActivity" ascii //weight: 2
        $x_2_2 = "vvoReceiver" ascii //weight: 2
        $x_2_3 = "s1iService" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

