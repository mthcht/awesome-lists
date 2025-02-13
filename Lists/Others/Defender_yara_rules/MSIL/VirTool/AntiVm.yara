rule VirTool_MSIL_AntiVm_GG_2147745516_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AntiVm.GG!MTB"
        threat_id = "2147745516"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AntiVm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Inject" ascii //weight: 10
        $x_10_2 = "\\RegAsm.exe" ascii //weight: 10
        $x_10_3 = "/C choice /C Y /N /D Y /T 3 & Del \"" ascii //weight: 10
        $x_1_4 = "powershell" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "Drop" ascii //weight: 1
        $x_1_7 = "vmware" ascii //weight: 1
        $x_1_8 = "qemu" ascii //weight: 1
        $x_1_9 = "VIRTUALBOX" ascii //weight: 1
        $x_1_10 = "vbox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_AntiVm_GG_2147745516_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AntiVm.GG!MTB"
        threat_id = "2147745516"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AntiVm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "schtasks" ascii //weight: 10
        $x_1_2 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_1_3 = "vmware" ascii //weight: 1
        $x_1_4 = "SbieDll.dll" ascii //weight: 1
        $x_1_5 = "VIRTUALBOX" ascii //weight: 1
        $x_1_6 = "Select * from Win32_ComputerSystem" ascii //weight: 1
        $x_1_7 = "Pastebin" ascii //weight: 1
        $x_1_8 = "%appdata%" ascii //weight: 1
        $x_1_9 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii //weight: 1
        $x_1_10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

