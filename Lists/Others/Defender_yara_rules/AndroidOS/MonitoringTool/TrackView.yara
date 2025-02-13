rule MonitoringTool_AndroidOS_TrackView_D_366231_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/TrackView.D!MTB"
        threat_id = "366231"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "TrackView"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/homesafe/call" ascii //weight: 1
        $x_1_2 = "LocationHistoryService" ascii //weight: 1
        $x_1_3 = "trackview:/payment_result?" ascii //weight: 1
        $x_1_4 = "LocationRecordData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_TrackView_E_410592_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/TrackView.E!MTB"
        threat_id = "410592"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "TrackView"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallActivity" ascii //weight: 1
        $x_1_2 = "ConnectionMsg" ascii //weight: 1
        $x_1_3 = "trackview:/payment_result?" ascii //weight: 1
        $x_1_4 = "app.cybrook.viewer" ascii //weight: 1
        $x_1_5 = "com.homesafe.sender.LoginCallbackActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

