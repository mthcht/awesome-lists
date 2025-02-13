rule MonitoringTool_AndroidOS_MobileSpy_179470_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobileSpy"
        threat_id = "179470"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobileSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MobileNannyLock" ascii //weight: 1
        $x_1_2 = "show Block list" ascii //weight: 1
        $x_1_3 = "nannylog.txt" ascii //weight: 1
        $x_1_4 = "uploading gps-->" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_MobileSpy_179470_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobileSpy"
        threat_id = "179470"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobileSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "does  not match..!!Please Re-enter." ascii //weight: 1
        $x_1_2 = "calllog.php?" ascii //weight: 1
        $x_1_3 = "mobilespy" ascii //weight: 1
        $x_1_4 = "remove these people?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_MobileSpy_A_309274_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobileSpy.A!MTB"
        threat_id = "309274"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobileSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RecordCalllogs" ascii //weight: 1
        $x_1_2 = "MobileSpy" ascii //weight: 1
        $x_1_3 = "gpslog.php" ascii //weight: 1
        $x_1_4 = "outgoingCallRecord" ascii //weight: 1
        $x_1_5 = "WIPE_LOG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

