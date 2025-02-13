rule Trojan_AndroidOS_KeyLogger_A_2147807432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/KeyLogger.A"
        threat_id = "2147807432"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "KeyLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_palysmudic" ascii //weight: 1
        $x_1_2 = "filinfodat" ascii //weight: 1
        $x_1_3 = "isAccessServiceEnabled" ascii //weight: 1
        $x_1_4 = "Laira/vat/" ascii //weight: 1
        $x_1_5 = "_phidatsu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

