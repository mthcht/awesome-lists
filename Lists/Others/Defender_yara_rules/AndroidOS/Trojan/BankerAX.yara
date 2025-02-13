rule Trojan_AndroidOS_BankerAX_A_2147830883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAX.A"
        threat_id = "2147830883"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAX"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.sk.axisbank" ascii //weight: 2
        $x_2_2 = "axisstore.in/api/points.php" ascii //weight: 2
        $x_2_3 = "KEY_ETUSERNAME" ascii //weight: 2
        $x_2_4 = "uremia" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

