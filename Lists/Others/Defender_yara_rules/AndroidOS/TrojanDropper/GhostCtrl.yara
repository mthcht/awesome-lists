rule TrojanDropper_AndroidOS_GhostCtrl_A_2147781078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/GhostCtrl.A!MTB"
        threat_id = "2147781078"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "GhostCtrl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/android.engine.apk" ascii //weight: 1
        $x_1_2 = "DIRECTORY_DOWNLOADS" ascii //weight: 1
        $x_1_3 = "/content/ComponentName" ascii //weight: 1
        $x_1_4 = "Application is not compatible with your android version" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

