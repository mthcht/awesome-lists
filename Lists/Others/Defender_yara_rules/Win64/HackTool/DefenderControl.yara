rule HackTool_Win64_DefenderControl_NIT_2147941021_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/DefenderControl.NIT!MTB"
        threat_id = "2147941021"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "DefenderControl"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DefenderControl" ascii //weight: 2
        $x_2_2 = "Command Add-MpPreference -ExclusionPath" ascii //weight: 2
        $x_2_3 = "dControl" ascii //weight: 2
        $x_1_4 = "@echo off" ascii //weight: 1
        $x_1_5 = "cmd /c del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

