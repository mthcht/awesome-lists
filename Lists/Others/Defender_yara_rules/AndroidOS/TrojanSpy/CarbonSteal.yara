rule TrojanSpy_AndroidOS_CarbonSteal_A_2147793209_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/CarbonSteal.A!MTB"
        threat_id = "2147793209"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "CarbonSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RobMoneyService" ascii //weight: 1
        $x_1_2 = "Calllogger" ascii //weight: 1
        $x_1_3 = "/filesManager/uploadFile" ascii //weight: 1
        $x_1_4 = "/triggerInfoManager/addTriggerInfo" ascii //weight: 1
        $x_1_5 = "screencap -p" ascii //weight: 1
        $x_1_6 = "6006.upupdate.cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

