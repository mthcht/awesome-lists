rule MonitoringTool_AndroidOS_GPSpy_A_303562_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/GPSpy.A!MTB"
        threat_id = "303562"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "GPSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gpspy" ascii //weight: 1
        $x_1_2 = "MobileGpspy.com" ascii //weight: 1
        $x_1_3 = "hide the Mobile-GPSpy" ascii //weight: 1
        $x_1_4 = "Lcom/spy/SendGPSPositions" ascii //weight: 1
        $x_1_5 = "Enable GPS satellites" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_GPSpy_B_357609_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/GPSpy.B!MTB"
        threat_id = "357609"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "GPSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.databackup.bo" ascii //weight: 1
        $x_1_2 = "gps_root_ll" ascii //weight: 1
        $x_1_3 = "InternetLocationLoader" ascii //weight: 1
        $x_1_4 = "SettingsActivity_permissions_required" ascii //weight: 1
        $x_1_5 = "Wi-Fi track" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

