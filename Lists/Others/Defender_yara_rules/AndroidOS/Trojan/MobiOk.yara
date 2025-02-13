rule Trojan_AndroidOS_MobiOk_A_2147789253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/MobiOk.A!MTB"
        threat_id = "2147789253"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "MobiOk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cloleect sms---" ascii //weight: 1
        $x_1_2 = "2captcha.com/in.php" ascii //weight: 1
        $x_1_3 = "sendMultipartSms" ascii //weight: 1
        $x_1_4 = "Upload/Processing.php" ascii //weight: 1
        $x_1_5 = "onJsGetPhoneNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

