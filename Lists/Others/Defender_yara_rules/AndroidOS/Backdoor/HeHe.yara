rule Backdoor_AndroidOS_HeHe_A_2147782153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/HeHe.A!MTB"
        threat_id = "2147782153"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "HeHe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IncomeCallAndSmsReceiver" ascii //weight: 1
        $x_1_2 = "delete sms call" ascii //weight: 1
        $x_1_3 = "transferCallInfo" ascii //weight: 1
        $x_1_4 = "msg.apk" ascii //weight: 1
        $x_1_5 = "SilenceInstall" ascii //weight: 1
        $x_1_6 = "interceptInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

