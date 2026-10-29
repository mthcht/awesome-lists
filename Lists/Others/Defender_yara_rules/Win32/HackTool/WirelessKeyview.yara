rule HackTool_Win32_WirelessKeyview_2147981158_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/WirelessKeyview!MTB"
        threat_id = "2147981158"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "WirelessKeyview"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Wireless Key View" wide //weight: 5
        $x_1_2 = "Extracts wireless keys stored by Windows" wide //weight: 1
        $x_1_3 = "NirSoft" wide //weight: 1
        $x_1_4 = "LOAD #25 poweroff" wide //weight: 1
        $x_1_5 = "Load the wireless keys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

