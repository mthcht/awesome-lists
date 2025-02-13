rule MonitoringTool_Win32_ShadowKeylogger_155268_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/ShadowKeylogger"
        threat_id = "155268"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Password for stopping the keylogging proccess." wide //weight: 1
        $x_1_2 = "Enable Screenshot Capturing" wide //weight: 1
        $x_2_3 = "Shadow_Keylogger.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

