rule MonitoringTool_AndroidOS_Stealthcell_B_347829_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Stealthcell.B!MTB"
        threat_id = "347829"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Stealthcell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.infoweise.parentalcontrol.secureteen.child" ascii //weight: 1
        $x_1_2 = "EmailGPSService" ascii //weight: 1
        $x_1_3 = "CallParrentActivity" ascii //weight: 1
        $x_1_4 = "secureteen.com/login.php?user_name=" ascii //weight: 1
        $x_1_5 = "ParentSelectDeviceActivity" ascii //weight: 1
        $x_1_6 = "tbl_app_usage_stat_lollipop" ascii //weight: 1
        $x_1_7 = "/secure/update/logs/summary?mappingId=" ascii //weight: 1
        $x_1_8 = "/secure/validate/usr/pwd/code" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

