rule Trojan_AndroidOS_Soumnibot_UT_2147919999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Soumnibot.UT"
        threat_id = "2147919999"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Soumnibot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://149.102.243.157:8077" ascii //weight: 1
        $x_1_2 = "http://172.247.39.154" ascii //weight: 1
        $x_1_3 = "http://89.187.184.213" ascii //weight: 1
        $x_1_4 = "handleMessage startService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

