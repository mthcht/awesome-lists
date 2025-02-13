rule Trojan_AndroidOS_Tetus_A_2147679397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Tetus.A"
        threat_id = "2147679397"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Tetus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&type=marketreciever&log=" ascii //weight: 1
        $x_1_2 = "MarketReciever.java" ascii //weight: 1
        $x_1_3 = "tetulus.com/atp-analytics.php?" ascii //weight: 1
        $x_1_4 = "&type=smsreciever&log=" ascii //weight: 1
        $x_1_5 = "/__utm.gif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

