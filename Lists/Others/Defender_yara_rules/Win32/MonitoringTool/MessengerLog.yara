rule MonitoringTool_Win32_MessengerLog_154354_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/MessengerLog"
        threat_id = "154354"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MessengerLog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 00 25 00 73 00 6d 00 6c 00 33 00 36 00 30 00 2e 00 64 00 6c 00 6c 00 22 00 20 00 53 00 74 00 61 00 72 00 74 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 4c 00 6f 00 67 00 20 00 33 00 36 00 30 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 20 00 74 00 68 00 72 00 65 00 61 00 64 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 64 00 2c 00 20 00 54 00 49 00 44 00 3a 00 20 00 25 00 64 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_MessengerLog_154354_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/MessengerLog"
        threat_id = "154354"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MessengerLog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe \"%sml360.dll\" StartMonitor" wide //weight: 1
        $x_1_2 = "ML360Srv.IServController = s 'IServController Class'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_MessengerLog_154354_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/MessengerLog"
        threat_id = "154354"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MessengerLog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Chat Log from MessengerLog 360" ascii //weight: 2
        $x_1_2 = "(LogUploader::UploadLog) Chat log upload failed via FTP." ascii //weight: 1
        $x_1_3 = "(ChatLog2::WriteLog) Can not zip file %s: %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

