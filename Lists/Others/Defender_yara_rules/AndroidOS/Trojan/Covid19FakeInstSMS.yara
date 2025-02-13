rule Trojan_AndroidOS_Covid19FakeInstSMS_2147783056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Covid19FakeInstSMS"
        threat_id = "2147783056"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Covid19FakeInstSMS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "tiny.cc/COVID-VACCINE" ascii //weight: 2
        $x_2_2 = "/chapkadhav" ascii //weight: 2
        $x_2_3 = "VacRegist app" ascii //weight: 2
        $x_2_4 = "Need Permission to start app!!" ascii //weight: 2
        $x_2_5 = "click on ad and install app to continue!!" ascii //weight: 2
        $x_3_6 = {1a 01 0e 00 1a 02 0f 00 1a 03 10 00 1a 04 11 00 1a 05 12 00 1a 06 13 00 1a 07 14 00 1a 08 15 00 1a 09 16 00 1a 0a 17 00 1a 0b 18 00 1a 0c 19 00 1a 0d 1a 00 1a 0e 1b 00 1a 0f 1c 00 1a 10 1d 00 [0-82] 74 01 f5 01 1d 00 0c 02 22 03 6d 01 70 10 f7 01 03 00 1a 04 23 00 6e 20 f9 01 43 00 0c 03 46 04 00 01}  //weight: 3, accuracy: Low
        $x_3_7 = "aHR0cDovL3RpbnkuY2MvQ08tUkVHSQ" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

