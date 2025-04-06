rule MonitoringTool_MacOS_Spyrix_DS_329160_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.DS!MTB"
        threat_id = "329160"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spyrix.SPScreenshots" ascii //weight: 1
        $x_1_2 = "com.spyrix.skm" ascii //weight: 1
        $x_1_3 = "/monitor/iupload.php" ascii //weight: 1
        $x_1_4 = "startMonitoringClipboard" ascii //weight: 1
        $x_1_5 = "CallRecordViewController" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_MacOS_Spyrix_A_345574_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.A!MTB"
        threat_id = "345574"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isMonitoringKeylogger" ascii //weight: 1
        $x_1_2 = "isEnableAutoCallRecorder" ascii //weight: 1
        $x_1_3 = "monitor/data_upload.php" ascii //weight: 1
        $x_1_4 = "LiveWebCam" ascii //weight: 1
        $x_1_5 = "com.spyrix.skm" ascii //weight: 1
        $x_1_6 = "ScreenRecorder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_MacOS_Spyrix_A_345574_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.A!MTB"
        threat_id = "345574"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.spyrix.skm" ascii //weight: 1
        $x_1_2 = "Spyrix.SPScreenshots" ascii //weight: 1
        $x_1_3 = "isMonitoringClipboard" ascii //weight: 1
        $x_1_4 = "spyrix.net/usr/monitor/iorder.php?id=%@" ascii //weight: 1
        $x_1_5 = "SPMonitoringKeyboardDelegate" ascii //weight: 1
        $x_1_6 = "monitor/upload3.php" ascii //weight: 1
        $x_1_7 = "spyrix-keylogger-for-mac-manual.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule MonitoringTool_MacOS_Spyrix_K_418697_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.K!MTB"
        threat_id = "418697"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "com.spyrix.skm" ascii //weight: 3
        $x_1_2 = "monitor/upload" ascii //weight: 1
        $x_1_3 = "/monitor/iupload" ascii //weight: 1
        $x_1_4 = "dashboard.spyrix.com/" ascii //weight: 1
        $x_1_5 = "/Library/skm/Spyrix.app" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_MacOS_Spyrix_J_418698_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.J!MTB"
        threat_id = "418698"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "com.actual.akm" ascii //weight: 3
        $x_3_2 = "com.spyrix.apskm" ascii //weight: 3
        $x_1_3 = "dashboard.spyrix.com/" ascii //weight: 1
        $x_1_4 = "/Library/akm/Spyrix.app" ascii //weight: 1
        $x_1_5 = "pathSpyrix" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_MacOS_Spyrix_B_449777_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.B!MTB"
        threat_id = "449777"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dashboard.spyrix.com/client-tech-logs/get-last-time?comp_id=" ascii //weight: 1
        $x_1_2 = "spyrix.net/usr/monitor/upload_prg.php" ascii //weight: 1
        $x_1_3 = "isMonitoringKeylogger" ascii //weight: 1
        $x_1_4 = "monitoringAudioDevices" ascii //weight: 1
        $x_1_5 = "videoWebCamRecorderManager" ascii //weight: 1
        $x_1_6 = "settings:enableCallRecording" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_MacOS_Spyrix_R_450448_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.R!MTB"
        threat_id = "450448"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "spyrix.net/usr/monitor/getsettings.php" ascii //weight: 1
        $x_1_2 = "monitor/iupload.php" ascii //weight: 1
        $x_1_3 = "account/check-subscription" ascii //weight: 1
        $x_1_4 = "pathSpyrix" ascii //weight: 1
        $x_1_5 = "dashboard.spyrix.com/" ascii //weight: 1
        $x_1_6 = "spyrix.net/usr/monitor/upload_prg.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule MonitoringTool_MacOS_Spyrix_C_452031_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.C!MTB"
        threat_id = "452031"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f3 03 01 aa f4 03 00 aa 20 11 00 f0 00 a0 28 91 63 58 fc 97 e2 03 00 aa 08 80 5f f8 03 01 40 f9 e0 03 14 aa e1 03 13 aa fd 7b 41 a9 f4 4f c2 a8 60 00 1f d6}  //weight: 1, accuracy: High
        $x_1_2 = {ff 03 02 d1 fc 6f 02 a9 fa 67 03 a9 f8 5f 04 a9 f6 57 05 a9 f4 4f 06 a9 fd 7b 07 a9 fd c3 01 91 28 11 00 d0 08 0d 46 f9 93 02 08 8b e1 23 00 91 e0 03 13 aa 02 00 80 d2 03 00 80 d2 9b a4 05 94 73 02 40 f9 68 fe 7e d3 a8 0c 00 b5 68 e2 7d 92 14 09 40 f9 e0 03 13 aa 41 00 80 52 9f a4 05 94 34 0d 00 b4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_MacOS_Spyrix_D_454393_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.D!MTB"
        threat_id = "454393"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.spyrix.emp-helper" ascii //weight: 1
        $x_1_2 = "group.com.spyrix.emp.share" ascii //weight: 1
        $x_1_3 = "/Library/emp/Spyrix.app" ascii //weight: 1
        $x_1_4 = "dashboard.spyrix.com/prg-actions" ascii //weight: 1
        $x_1_5 = "$s13Spyrix_Helper23_ACResourceInitProtocolP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

