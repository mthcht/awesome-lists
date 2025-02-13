rule Trojan_AndroidOS_FakeLogoSms_A_2147652260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeLogoSms.A"
        threat_id = "2147652260"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeLogoSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d0 9b d0 b8 d0 b1 d0 be 20 d0 bf d0 b5 d1 80 d0 b5 d0 b9 d1 82 d0 b8 20 d0 bf d1 80 d1 8f d0 bc d0 be 20 d0 b8 d0 b7 20 53 4d 53 2e}  //weight: 1, accuracy: High
        $x_1_2 = "pushme/android/Pushme" ascii //weight: 1
        $x_1_3 = "app_name_skaype" ascii //weight: 1
        $x_1_4 = "Pushme.java" ascii //weight: 1
        $x_1_5 = "rules.htm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

