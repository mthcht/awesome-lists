rule MonitoringTool_AndroidOS_XnSpy_A_347621_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/XnSpy.A!MTB"
        threat_id = "347621"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "XnSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "executeUpload" ascii //weight: 1
        $x_1_2 = "SMS log upload" ascii //weight: 1
        $x_1_3 = "XNSPY" ascii //weight: 1
        $x_1_4 = "Browseing History executeBackup" ascii //weight: 1
        $x_1_5 = "contactLogBackup" ascii //weight: 1
        $x_1_6 = "callRecordingUpload" ascii //weight: 1
        $x_1_7 = "updateInstallAppLogForSync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_XnSpy_B_360475_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/XnSpy.B!MTB"
        threat_id = "360475"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "XnSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wipePhoneAndScreenshot" ascii //weight: 1
        $x_1_2 = "ContactWatchList" ascii //weight: 1
        $x_1_3 = "/payload/smsdetail" ascii //weight: 1
        $x_1_4 = "/payload/imsglogdetail" ascii //weight: 1
        $x_1_5 = "Lcom/xnspy/dashboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

