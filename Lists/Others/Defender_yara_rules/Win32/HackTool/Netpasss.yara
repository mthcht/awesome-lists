rule HackTool_Win32_Netpasss_AB_2147817179_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Netpasss.AB!MTB"
        threat_id = "2147817179"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Netpasss"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WNetEnumCachedPasswords" ascii //weight: 1
        $x_1_2 = "nirsoft.net" ascii //weight: 1
        $x_1_3 = "Export Raw Passwords Data" ascii //weight: 1
        $x_1_4 = "Network Password Recovery" ascii //weight: 1
        $x_1_5 = "Network Passwords List" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

