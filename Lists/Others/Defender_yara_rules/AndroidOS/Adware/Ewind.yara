rule Adware_AndroidOS_Ewind_A_304643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Ewind.A"
        threat_id = "304643"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Ewind"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HeyHey" ascii //weight: 1
        $x_1_2 = "AliveEventSendAlarm" ascii //weight: 1
        $x_1_3 = "CryopiggyApplication" ascii //weight: 1
        $x_1_4 = "isImpressionWasDone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_Ewind_B_330920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Ewind.B"
        threat_id = "330920"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Ewind"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "manager/lockscreen/LockscreenManagerImpl" ascii //weight: 1
        $x_1_2 = "startScreenReceiver" ascii //weight: 1
        $x_1_3 = "unlockAdDetector" ascii //weight: 1
        $x_1_4 = "sdk/service/detector/Detector" ascii //weight: 1
        $x_1_5 = "showLockscreenAdTaskFactory" ascii //weight: 1
        $x_1_6 = "CryopiggyApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

