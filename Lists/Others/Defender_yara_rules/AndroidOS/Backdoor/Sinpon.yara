rule Backdoor_AndroidOS_Sinpon_A_2147828251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Sinpon.A!MTB"
        threat_id = "2147828251"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Sinpon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BackConnTask" ascii //weight: 1
        $x_1_2 = "result_InstalledApp" ascii //weight: 1
        $x_1_3 = "getkernelApp" ascii //weight: 1
        $x_1_4 = "SendSmsMes" ascii //weight: 1
        $x_1_5 = "killFile" ascii //weight: 1
        $x_1_6 = "PhoneSyncService" ascii //weight: 1
        $x_1_7 = "UploadTask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

