rule VirTool_MSIL_Antisow_A_2147692121_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Antisow.A"
        threat_id = "2147692121"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Antisow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KazyRootkit" ascii //weight: 1
        $x_1_2 = "HideProcess" ascii //weight: 1
        $x_1_3 = "HideRegistryValue" ascii //weight: 1
        $x_1_4 = "/c echo [zoneTransfer]ZoneID = 2 > \"" wide //weight: 1
        $x_1_5 = "\":ZONE.identifier & exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Antisow_A_2147692121_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Antisow.A"
        threat_id = "2147692121"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Antisow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiEmulation" ascii //weight: 1
        $x_1_2 = "AntiSandboxie" ascii //weight: 1
        $x_1_3 = "DetectWPE" ascii //weight: 1
        $x_1_4 = "DetectWireshark" ascii //weight: 1
        $x_1_5 = "DisableUAC" ascii //weight: 1
        $x_1_6 = "DownRun" ascii //weight: 1
        $x_1_7 = "HiddenStartup" ascii //weight: 1
        $x_1_8 = "KillProc" ascii //weight: 1
        $x_1_9 = "GetInjectionPath" ascii //weight: 1
        $x_1_10 = "-keyhide" wide //weight: 1
        $x_1_11 = "-prochide" wide //weight: 1
        $x_1_12 = "-prockill" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

