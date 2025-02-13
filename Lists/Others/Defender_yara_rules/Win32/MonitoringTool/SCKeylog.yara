rule MonitoringTool_Win32_SCKeylog_228361_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SCKeylog!bit"
        threat_id = "228361"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SCKeylog"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Soft-Central's SC-KeyLog" wide //weight: 1
        $x_1_2 = "Software\\SoftCentral\\SC-KeyLog" ascii //weight: 1
        $x_1_3 = "X-Mailer: SC-KL Mail service" ascii //weight: 1
        $x_1_4 = "Open SC-KeyLog homepage" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

