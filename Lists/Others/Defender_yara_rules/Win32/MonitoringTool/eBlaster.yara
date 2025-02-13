rule MonitoringTool_Win32_eBlaster_4763_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/eBlaster"
        threat_id = "4763"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "eBlaster"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Click here to tell a friend about eBlaster:" wide //weight: 5
        $x_3_2 = "Please contact SpectorSoft at www.spectorsoft.com" wide //weight: 3
        $x_5_3 = "Your eBlaster Serial number is invalid." wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

