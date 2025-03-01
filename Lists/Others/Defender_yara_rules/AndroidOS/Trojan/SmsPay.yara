rule Trojan_AndroidOS_SmsPay_C_2147843815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsPay.C"
        threat_id = "2147843815"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsPay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".receiver.InSmsReceiver" ascii //weight: 2
        $x_2_2 = "startSdkServerPay" ascii //weight: 2
        $x_2_3 = ".services.SmsDataService" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

