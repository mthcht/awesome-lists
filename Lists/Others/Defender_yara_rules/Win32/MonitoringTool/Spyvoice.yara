rule MonitoringTool_Win32_Spyvoice_205218_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Spyvoice"
        threat_id = "205218"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyvoice"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SKYPE4COMLib" ascii //weight: 1
        $x_1_2 = "hkHideRun" ascii //weight: 1
        $x_1_3 = "KeyLogger" wide //weight: 1
        $x_1_4 = "Spy Voice Recorder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

