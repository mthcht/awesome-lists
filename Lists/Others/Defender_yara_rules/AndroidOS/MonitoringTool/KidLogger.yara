rule MonitoringTool_AndroidOS_KidLogger_A_299238_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/KidLogger.A!MTB"
        threat_id = "299238"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "KidLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "logCalls" ascii //weight: 1
        $x_1_2 = "getKeystroke" ascii //weight: 1
        $x_1_3 = "uploadKey" ascii //weight: 1
        $x_1_4 = "KidLocListener" ascii //weight: 1
        $x_1_5 = "net.kidlogger" ascii //weight: 1
        $x_1_6 = "loggerkeyboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_KidLogger_D_332010_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/KidLogger.D!MTB"
        threat_id = "332010"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "KidLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kidlogger.net" ascii //weight: 1
        $x_1_2 = "logCalls" ascii //weight: 1
        $x_1_3 = "getKeystroke" ascii //weight: 1
        $x_1_4 = "logClipboard" ascii //weight: 1
        $x_1_5 = "uploadKey" ascii //weight: 1
        $x_1_6 = "KidLocListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_AndroidOS_KidLogger_B_332011_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/KidLogger.B!MTB"
        threat_id = "332011"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "KidLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "net.kdl.talkbackts" ascii //weight: 2
        $x_1_2 = "TakeExtraordinaryScreenshot" ascii //weight: 1
        $x_1_3 = "SendUrlToLog" ascii //weight: 1
        $x_1_4 = "blockApp" ascii //weight: 1
        $x_1_5 = "Descr_or_URL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_AndroidOS_KidLogger_C_332065_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/KidLogger.C!MTB"
        threat_id = "332065"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "KidLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net/someapp1/keyboard" ascii //weight: 1
        $x_1_2 = "LaunchKidLogger" ascii //weight: 1
        $x_1_3 = "sendKey" ascii //weight: 1
        $x_1_4 = "sendToService" ascii //weight: 1
        $x_1_5 = "sendString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

