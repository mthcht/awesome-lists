rule MonitoringTool_AndroidOS_SPAPP_A_298992_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SPAPP.A!MTB"
        threat_id = "298992"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SPAPP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SPAPP Monitoring" ascii //weight: 1
        $x_1_2 = "www.Spy-datacenter.com/send_data.php" ascii //weight: 1
        $x_1_3 = "com.spyapp.webbrowser" ascii //weight: 1
        $x_1_4 = "ph_administrator_rights_enabled" ascii //weight: 1
        $x_1_5 = "enable_remote_wipe" ascii //weight: 1
        $x_1_6 = "recording_phone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

