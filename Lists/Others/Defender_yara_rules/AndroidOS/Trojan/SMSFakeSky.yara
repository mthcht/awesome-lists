rule Trojan_AndroidOS_SMSFakeSky_A_2147658542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSFakeSky.A"
        threat_id = "2147658542"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSFakeSky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KwrhReceiveR.java" ascii //weight: 1
        $x_1_2 = "Checking for sending another SMS." ascii //weight: 1
        $x_1_3 = "raw/data.dat" ascii //weight: 1
        $x_1_4 = "android_asset/test.html#loaded=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

