rule MonitoringTool_AndroidOS_SpyHuman_B_329271_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyHuman.B!MTB"
        threat_id = "329271"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyHuman"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpyHumanUpload" ascii //weight: 1
        $x_1_2 = "SpyHumanLocation" ascii //weight: 1
        $x_1_3 = "spyhuman.com" ascii //weight: 1
        $x_1_4 = "/.tmpysk" ascii //weight: 1
        $x_1_5 = "PhneListener" ascii //weight: 1
        $x_1_6 = "senddata" ascii //weight: 1
        $x_1_7 = "smsall.php" ascii //weight: 1
        $x_1_8 = "storephoninfo.php" ascii //weight: 1
        $x_1_9 = "calllogs.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule MonitoringTool_AndroidOS_SpyHuman_C_331842_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyHuman.C!MTB"
        threat_id = "331842"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyHuman"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "apispyhuman.com" ascii //weight: 1
        $x_1_2 = "activity_monitoring_opation" ascii //weight: 1
        $x_1_3 = "install_Monitoring_Type_activity" ascii //weight: 1
        $x_1_4 = "Readallcontects" ascii //weight: 1
        $x_1_5 = "AppFeturesMan" ascii //weight: 1
        $x_1_6 = "Brodcast_Call" ascii //weight: 1
        $x_1_7 = "smsupload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_AndroidOS_SpyHuman_D_349981_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyHuman.D!MTB"
        threat_id = "349981"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyHuman"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "notificationtrack" ascii //weight: 1
        $x_1_2 = "com.antitheftservice" ascii //weight: 1
        $x_1_3 = "Welcome_spyhuman" ascii //weight: 1
        $x_1_4 = "WatchDogServiceReceiver" ascii //weight: 1
        $x_1_5 = "monitoring_opation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

