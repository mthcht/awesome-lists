rule MonitoringTool_AndroidOS_MobiStealth_AS_298773_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobiStealth.AS!MTB"
        threat_id = "298773"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobiStealth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StealthWipeSMSProcessor" ascii //weight: 1
        $x_1_2 = "mobistealth" ascii //weight: 1
        $x_1_3 = "CallRecording" ascii //weight: 1
        $x_1_4 = "calllog.dat" ascii //weight: 1
        $x_1_5 = "call is ringing" ascii //weight: 1
        $x_1_6 = "phonewipeinfo.dat" ascii //weight: 1
        $x_1_7 = "All Data on phone has been wiped out" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_MobiStealth_A_444024_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobiStealth.A!MTB"
        threat_id = "444024"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobiStealth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mobistealth" ascii //weight: 1
        $x_1_2 = "smslog.dat" ascii //weight: 1
        $x_1_3 = "StealthBackUpData" ascii //weight: 1
        $x_1_4 = "EmailCallRecordingService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

