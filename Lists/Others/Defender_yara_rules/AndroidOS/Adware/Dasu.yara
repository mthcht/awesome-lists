rule Adware_AndroidOS_Dasu_A_346228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Dasu.A!MTB"
        threat_id = "346228"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Dasu"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 00 54 31 [0-16] 21 00 22 00 [0-6] 00 00 1a 01 [0-6] 10 00 54 31 [0-16] 21 00 22 00 [0-6] 00 00 22 00 [0-6] 00 00 1a 01 [0-6] 10 00 54 31}  //weight: 1, accuracy: Low
        $x_1_2 = "Txwp3PIfYZBqX/ERQkd5xBxF0XQ" ascii //weight: 1
        $x_1_3 = "com/loader/activity/PA" ascii //weight: 1
        $x_1_4 = "DexClassLoader" ascii //weight: 1
        $x_1_5 = "getRunningTasks" ascii //weight: 1
        $x_1_6 = "setAutoCancel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

