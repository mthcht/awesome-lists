rule Trojan_AndroidOS_GossRat_B_2147895640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GossRat.B"
        threat_id = "2147895640"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GossRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "This_Is_The_VVay" ascii //weight: 2
        $x_2_2 = "testhadirattest/ServiceRead" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

