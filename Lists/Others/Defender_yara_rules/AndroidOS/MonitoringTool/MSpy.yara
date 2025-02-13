rule MonitoringTool_AndroidOS_MSpy_B_348546_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MSpy.B!MTB"
        threat_id = "348546"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "apphelper.idevs.co" ascii //weight: 1
        $x_1_2 = "InstagramGrabber" ascii //weight: 1
        $x_1_3 = "KeyLoggerSensorController" ascii //weight: 1
        $x_1_4 = "mspy_keyboard" ascii //weight: 1
        $x_1_5 = "WhatsAppSensor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_MSpy_D_362806_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MSpy.D!MTB"
        threat_id = "362806"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.mspy.lite" ascii //weight: 1
        $x_1_2 = "OnboardingTrackNumber" ascii //weight: 1
        $x_1_3 = "OnboardingSurroundingsRecording" ascii //weight: 1
        $x_1_4 = "injectChildLocationSent" ascii //weight: 1
        $x_1_5 = "injectChildContactSent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

