rule HackTool_MSIL_Protoon_A_2147692184_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Protoon.A"
        threat_id = "2147692184"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Protoon"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProtonCrypt" ascii //weight: 1
        $x_1_2 = "FilemanagerClient" ascii //weight: 1
        $x_1_3 = "HandleLockFileCommands" ascii //weight: 1
        $x_1_4 = "HandleSendCommands" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_Protoon_A_2147692184_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Protoon.A"
        threat_id = "2147692184"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Protoon"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SystemToolsClient" ascii //weight: 1
        $x_1_2 = "HandleConsoleCommands" ascii //weight: 1
        $x_1_3 = "HandleTaskManagerCommands" ascii //weight: 1
        $x_1_4 = "HandleRegistryCommands" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_Protoon_A_2147692184_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Protoon.A"
        threat_id = "2147692184"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Protoon"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FunnyToolsClient" ascii //weight: 1
        $x_1_2 = "HardwareCommands" ascii //weight: 1
        $x_1_3 = "HandleMiscCommands" ascii //weight: 1
        $x_1_4 = "set CDAudio door open" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_Protoon_A_2147692184_3
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Protoon.A"
        threat_id = "2147692184"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Protoon"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keyboard Log - Proton RAT" ascii //weight: 1
        $x_1_2 = "\\Proton\\KBLogs" wide //weight: 1
        $x_1_3 = "{0}\\KB-{1}.{2}.{3}.log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule HackTool_MSIL_Protoon_A_2147692184_4
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Protoon.A"
        threat_id = "2147692184"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Protoon"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HandleChatCommands" ascii //weight: 1
        $x_1_2 = "HandleUploadAndExecuteCommands" ascii //weight: 1
        $x_1_3 = "HandleDownloadAndExecuteCommands" ascii //weight: 1
        $x_1_4 = "HandleVisitWebsiteHiddenlyCommands" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_Protoon_A_2147692184_5
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Protoon.A"
        threat_id = "2147692184"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Protoon"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VideoSourcesCommands" ascii //weight: 1
        $x_1_2 = "PasswordRecoveryCommands" ascii //weight: 1
        $x_1_3 = "RemoteDesktopCommands" ascii //weight: 1
        $x_1_4 = "SurveillanceClient" ascii //weight: 1
        $x_1_5 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_MSIL_Protoon_A_2147692184_6
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Protoon.A"
        threat_id = "2147692184"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Protoon"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ClientPlugin" ascii //weight: 1
        $x_1_2 = "Pipedestroyed" ascii //weight: 1
        $x_1_3 = "RispsB483Ee2x71V4dym0Q==" wide //weight: 1
        $x_1_4 = "Loaded plugin: {0}, cached: {1}" wide //weight: 1
        $x_1_5 = "\" /SC ONCE /ST 00:00 /TR \"'cmd.exe' /C start \"\" \"" wide //weight: 1
        $x_1_6 = "\\Log.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

