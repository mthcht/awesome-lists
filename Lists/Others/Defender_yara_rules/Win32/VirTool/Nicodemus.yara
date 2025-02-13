rule VirTool_Win32_Nicodemus_A_2147818229_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Nicodemus.A!MTB"
        threat_id = "2147818229"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Nicodemus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nicodemus" ascii //weight: 1
        $x_1_2 = "beacon" ascii //weight: 1
        $x_1_3 = "@powershell.exe" ascii //weight: 1
        $x_1_4 = "newConnection" ascii //weight: 1
        $x_1_5 = "@sleep" ascii //weight: 1
        $x_1_6 = "@contact" ascii //weight: 1
        $x_1_7 = "@address" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

