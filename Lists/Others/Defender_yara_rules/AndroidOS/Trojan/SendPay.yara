rule Trojan_AndroidOS_Sendpay_A_2147909891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Sendpay.A"
        threat_id = "2147909891"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Sendpay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "destined_xhalf_free" ascii //weight: 1
        $x_1_2 = "Could not send sms to number" ascii //weight: 1
        $x_1_3 = "application/x-app-store" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

