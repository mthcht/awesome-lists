rule MonitoringTool_Win32_GuardianEye_170235_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/GuardianEye"
        threat_id = "170235"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GuardianEye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EmailToSendFrom=" wide //weight: 2
        $x_5_2 = "DisableRegEdit=Yes" wide //weight: 5
        $x_5_3 = "UseFTP=Yes" wide //weight: 5
        $x_6_4 = "moveToUSB" ascii //weight: 6
        $x_8_5 = "TGEYEFileName=" wide //weight: 8
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

