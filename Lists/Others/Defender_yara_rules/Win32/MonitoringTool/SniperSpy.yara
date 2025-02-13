rule MonitoringTool_Win32_SniperSpy_157583_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SniperSpy"
        threat_id = "157583"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SniperSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SniperSpy Configuration Module" ascii //weight: 3
        $x_3_2 = "http://www.sniperspy.com/guide.html" wide //weight: 3
        $x_2_3 = "lblRetinax" ascii //weight: 2
        $x_2_4 = "keylogger=true" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_SniperSpy_157583_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SniperSpy"
        threat_id = "157583"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SniperSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "<b>SniperSpy version:</b>" wide //weight: 8
        $x_8_2 = "SniperSpy\\FTPClass" wide //weight: 8
        $x_4_3 = "ctrlpanel/livedesk/arewelive.php" wide //weight: 4
        $x_4_4 = "\\livekeylog.lkl" wide //weight: 4
        $x_2_5 = "w.logsviewer.com" wide //weight: 2
        $x_2_6 = "mylogsviewer.com" wide //weight: 2
        $x_2_7 = "</Br>[<a href=setcommand.php" wide //weight: 2
        $x_1_8 = "KILLANTISPYWARE" wide //weight: 1
        $x_1_9 = "/livecommand.php" wide //weight: 1
        $x_1_10 = "/liveupload.php" wide //weight: 1
        $x_1_11 = "iCaptureInterval=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*))) or
            ((2 of ($x_8_*))) or
            (all of ($x*))
        )
}

