rule Backdoor_AndroidOS_CrWind_A_2147829708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/CrWind.A!MTB"
        threat_id = "2147829708"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "CrWind"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "postInSms" ascii //weight: 1
        $x_1_2 = "SMS_SENT" ascii //weight: 1
        $x_1_3 = "POST_APP_LIST" ascii //weight: 1
        $x_1_4 = "getSendNumber" ascii //weight: 1
        $x_1_5 = "unInstallApp" ascii //weight: 1
        $x_1_6 = "ttp://crusewind.net/flash" ascii //weight: 1
        $x_1_7 = "Lcom/flashp/FlashApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

