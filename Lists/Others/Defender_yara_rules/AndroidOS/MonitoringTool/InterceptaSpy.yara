rule MonitoringTool_AndroidOS_InterceptaSpy_A_324040_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/InterceptaSpy.A!MTB"
        threat_id = "324040"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "InterceptaSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "app-measurement.com" ascii //weight: 1
        $x_1_2 = "mobiopen.com/receiver/data" ascii //weight: 1
        $x_1_3 = "READ_CALL_LOG" ascii //weight: 1
        $x_1_4 = "org/webrtc/VideoCapturer" ascii //weight: 1
        $x_1_5 = "getLastKnownLocation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_InterceptaSpy_B_404466_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/InterceptaSpy.B!MTB"
        threat_id = "404466"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "InterceptaSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SCREEN_DONE_MONITOR" ascii //weight: 1
        $x_1_2 = "is_notif_ative" ascii //weight: 1
        $x_1_3 = "OnInfoListener" ascii //weight: 1
        $x_1_4 = "Lcom/android/system/activts/GetDataRecActivity" ascii //weight: 1
        $x_1_5 = "ServiceMonitor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

