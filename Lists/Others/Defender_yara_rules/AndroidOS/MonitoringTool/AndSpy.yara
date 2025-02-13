rule MonitoringTool_AndroidOS_AndSpy_B_298509_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/AndSpy.B!MTB"
        threat_id = "298509"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "AndSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "loongware.com" ascii //weight: 1
        $x_1_2 = "Action=Check&SoftName=AndSpy&RegCode" ascii //weight: 1
        $x_1_3 = {68 69 2e 62 61 69 64 75 2e 63 6f 6d 2f 66 69 6c 65 5f 63 6f 70 79 2f 62 6c 6f 67 2f 69 74 65 6d 2f [0-37] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_4 = "mobilelogger.net" ascii //weight: 1
        $x_1_5 = "/ml/manager/upload.php" ascii //weight: 1
        $x_1_6 = "MySendSMS" ascii //weight: 1
        $x_1_7 = "RecordCall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_AndroidOS_AndSpy_A_322242_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/AndSpy.A!MTB"
        threat_id = "322242"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "AndSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HeartbeatDispatcher" ascii //weight: 1
        $x_1_2 = "deleteBrowserHistory" ascii //weight: 1
        $x_1_3 = "spysetup.com" ascii //weight: 1
        $x_1_4 = "server.freeandroidspy.com/index.php" ascii //weight: 1
        $x_1_5 = "client_log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

