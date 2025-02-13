rule HackTool_Win32_Wgdrop_A_2147754249_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Wgdrop.A!MTB"
        threat_id = "2147754249"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Wgdrop"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "By WinEggDrop" ascii //weight: 20
        $x_1_2 = "System\\CurrentControlSet\\Services" ascii //weight: 1
        $x_1_3 = "install ServiceName DisplayName FileName" ascii //weight: 1
        $x_1_4 = "delete ServiceName" ascii //weight: 1
        $x_1_5 = "FILE_GENERIC_EXECUTE" ascii //weight: 1
        $x_1_6 = "\\Device\\HarddiskVolume" ascii //weight: 1
        $x_1_7 = "Modify File Permission OK" ascii //weight: 1
        $x_2_8 = "Kill The Process Successfully" ascii //weight: 2
        $x_1_9 = "SELECT ProcessId,ExecutablePath FROM Win32_Process" ascii //weight: 1
        $x_2_10 = "Infect IAT OK" ascii //weight: 2
        $x_1_11 = "/InfectAllDLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

