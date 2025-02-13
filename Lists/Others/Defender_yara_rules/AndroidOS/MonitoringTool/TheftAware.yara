rule MonitoringTool_AndroidOS_TheftAware_A_298993_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/TheftAware.A!MTB"
        threat_id = "298993"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "TheftAware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/system/app/at.itagents.ta.apk" ascii //weight: 1
        $x_1_2 = "TheftAwareInstaller.temp.apk" ascii //weight: 1
        $x_1_3 = "TheftAwareService" ascii //weight: 1
        $x_1_4 = "at.itagents.ta_setup_mf" ascii //weight: 1
        $x_1_5 = "www.theftaware.com" ascii //weight: 1
        $x_1_6 = "/tmp/at.itagents.ta.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

