rule MonitoringTool_AndroidOS_AxeSpy_A_404468_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/AxeSpy.A!MTB"
        threat_id = "404468"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "AxeSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.android.dmp" ascii //weight: 5
        $x_1_2 = "getCallRecordDsid" ascii //weight: 1
        $x_1_3 = "isCallRecord" ascii //weight: 1
        $x_1_4 = "/.utsk/" ascii //weight: 1
        $x_1_5 = "sp_restore_actions" ascii //weight: 1
        $x_1_6 = "deleteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

