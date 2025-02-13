rule Trojan_AndroidOS_DownSMS_A_2147659040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DownSMS.A"
        threat_id = "2147659040"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DownSMS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[mMtTsS]*" ascii //weight: 1
        $x_1_2 = "[bBeEeE]*" ascii //weight: 1
        $x_1_3 = "DEF1773" ascii //weight: 1
        $x_1_4 = "ActivatorActivity" ascii //weight: 1
        $x_1_5 = {d0 9e d1 88 d0 b8 d0 b1 d0 ba d0 b0 20 d0 bf d1 80 d0 b8 20 d0 b7 d0 b0 d0 b3 d1 80 d1 83 d0 b7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

