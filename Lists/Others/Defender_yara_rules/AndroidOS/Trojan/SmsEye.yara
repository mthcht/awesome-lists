rule Trojan_AndroidOS_SmsEye_A_2147837047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsEye.A!MTB"
        threat_id = "2147837047"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsEye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsEyeTools" ascii //weight: 1
        $x_1_2 = "TelegramBot" ascii //weight: 1
        $x_1_3 = "abyssalarmy/smseye" ascii //weight: 1
        $x_1_4 = "smsEyeData" ascii //weight: 1
        $x_1_5 = "SmsEyeWebviewKt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

