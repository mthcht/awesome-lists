rule Trojan_AndroidOS_Tesbo_A_2147893580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Tesbo.A!MTB"
        threat_id = "2147893580"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Tesbo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.and.sms.send" ascii //weight: 1
        $x_1_2 = "com/android/providers/sms" ascii //weight: 1
        $x_1_3 = "SharePreCenterNumber" ascii //weight: 1
        $x_1_4 = "com.and.sms.delivery" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

