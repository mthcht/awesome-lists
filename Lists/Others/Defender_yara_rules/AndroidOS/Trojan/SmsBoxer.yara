rule Trojan_AndroidOS_SmsBoxer_A_2147831581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsBoxer.A!MTB"
        threat_id = "2147831581"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsBoxer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ru/jabox/android/smsbox" ascii //weight: 1
        $x_1_2 = "AbstractSmsboxApplication" ascii //weight: 1
        $x_1_3 = "JokeBoxApplication" ascii //weight: 1
        $x_1_4 = "OurProjectsActivity" ascii //weight: 1
        $x_1_5 = "SexBoxApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

