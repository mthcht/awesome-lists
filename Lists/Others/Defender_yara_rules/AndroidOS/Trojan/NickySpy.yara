rule Trojan_AndroidOS_NickySpy_K_2147918413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/NickySpy.K"
        threat_id = "2147918413"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "NickySpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EnvirRecordService" ascii //weight: 2
        $x_2_2 = "nicky/lyyws/asl/SListener" ascii //weight: 2
        $x_2_3 = "nowsmsdate" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

