rule Trojan_AndroidOS_BRats_A_2147846452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BRats.A!MTB"
        threat_id = "2147846452"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BRats"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.orchestra.watchdog" ascii //weight: 1
        $x_1_2 = "NubankFacadeBill" ascii //weight: 1
        $x_1_3 = "fakePrice" ascii //weight: 1
        $x_1_4 = "PaymentHijarkTask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

