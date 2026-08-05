rule HackTool_MSIL_Dumper_SN_2147975296_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Dumper.SN!MTB"
        threat_id = "2147975296"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dumper"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CreateProcess hoocked!" wide //weight: 2
        $x_2_2 = "Start login hooks..." wide //weight: 2
        $x_2_3 = "Logging memcpy enabled!" wide //weight: 2
        $x_2_4 = "Dll injected at address:" wide //weight: 2
        $x_2_5 = "InjectManagedDllToolStripMenuItemClick" ascii //weight: 2
        $x_2_6 = "HookDetectionToolStripMenuItemClick" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

