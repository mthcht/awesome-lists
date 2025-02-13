rule MonitoringTool_AndroidOS_Valdo_A_340518_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Valdo.A!MTB"
        threat_id = "340518"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Valdo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FakeSocketFactory" ascii //weight: 1
        $x_1_2 = "SendPicAsync" ascii //weight: 1
        $x_5_3 = "com.vlado.prototype" ascii //weight: 5
        $x_1_4 = "lastContactDate" ascii //weight: 1
        $x_5_5 = "com.system.gps.tools.mmmonnnitor/databases/proto.db" ascii //weight: 5
        $x_1_6 = "extractBrowserHistory" ascii //weight: 1
        $x_1_7 = "extractWAmsg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

