rule Trojan_AndroidOS_SmsZombie_A_2147661074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsZombie.A"
        threat_id = "2147661074"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsZombie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Has do Clear logcat cache" ascii //weight: 1
        $x_1_2 = "/phone.xml" ascii //weight: 1
        $x_1_3 = "START111" ascii //weight: 1
        $x_1_4 = "AndphoneActivity.java" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsZombie_A_2147661074_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsZombie.A"
        threat_id = "2147661074"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsZombie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a33.jpg" ascii //weight: 1
        $x_1_2 = "baoxian_zhushou" ascii //weight: 1
        $x_1_3 = "NetworkPIN" ascii //weight: 1
        $x_1_4 = "data/android.phone.com/files/phone.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

