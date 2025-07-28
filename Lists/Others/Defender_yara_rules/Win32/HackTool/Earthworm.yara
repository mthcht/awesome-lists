rule HackTool_Win32_Earthworm_ME_2147947635_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Earthworm.ME!MTB"
        threat_id = "2147947635"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Earthworm"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "rootkiter" ascii //weight: 10
        $x_3_2 = "EarthWrom" ascii //weight: 3
        $x_3_3 = "EarthWorm" ascii //weight: 3
        $x_1_4 = "CONFIRM_YOU_ARE_SOCK_CLIENT" ascii //weight: 1
        $x_1_5 = "ssocksd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

