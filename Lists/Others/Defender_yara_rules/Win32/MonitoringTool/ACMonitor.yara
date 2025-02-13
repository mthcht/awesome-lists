rule MonitoringTool_Win32_ACMonitor_17859_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/ACMonitor"
        threat_id = "17859"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ACMonitor"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ACMLogViewer" ascii //weight: 2
        $x_2_2 = "://www.zemericks.com" wide //weight: 2
        $x_1_3 = "Performing cleanup...please wait." wide //weight: 1
        $x_1_4 = "Status: Decrypting Screen Captures...." wide //weight: 1
        $x_1_5 = "Status: Loading Thumbnails...." wide //weight: 1
        $x_1_6 = "Are you sure you want to clear this keystroke log?" wide //weight: 1
        $x_1_7 = "Deleting Screen Snapshots" wide //weight: 1
        $x_1_8 = "ACM Service Restarted" wide //weight: 1
        $x_1_9 = "Are you sure you want to delete all saved logs?" wide //weight: 1
        $x_1_10 = "Confirm Delete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

