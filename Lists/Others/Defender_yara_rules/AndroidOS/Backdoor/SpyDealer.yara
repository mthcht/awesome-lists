rule Backdoor_AndroidOS_SpyDealer_DS_2147785082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/SpyDealer.DS!MTB"
        threat_id = "2147785082"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "SpyDealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetHistoryCall" ascii //weight: 1
        $x_1_2 = "/status/deal/body/dealapp.asp" ascii //weight: 1
        $x_1_3 = "SMS_URI_ALL" ascii //weight: 1
        $x_1_4 = "getIncomeNumberAndTime" ascii //weight: 1
        $x_1_5 = "m_attackfile" ascii //weight: 1
        $x_1_6 = "autorepcallnum" ascii //weight: 1
        $x_1_7 = "startRoot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

