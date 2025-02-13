rule VirTool_Win32_ColorUAC_A_2147836058_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ColorUAC.A!MTB"
        threat_id = "2147836058"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ColorUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Elevation:Administrator!new:" ascii //weight: 1
        $x_1_2 = "CoGetObject" ascii //weight: 1
        $x_1_3 = "CoInitializeEx" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

