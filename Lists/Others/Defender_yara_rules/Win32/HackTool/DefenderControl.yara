rule HackTool_Win32_DefenderControl_A_2147779688_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DefenderControl.A!MTB"
        threat_id = "2147779688"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderControl"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DefenderControl.exe" wide //weight: 1
        $x_1_2 = "Turn Windows Defender off or on with administrator rights" wide //weight: 1
        $x_1_3 = "WinDetectHiddenText" wide //weight: 1
        $x_1_4 = "AU3_GetPluginDetails" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

