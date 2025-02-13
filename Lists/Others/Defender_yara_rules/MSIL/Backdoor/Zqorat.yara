rule Backdoor_MSIL_Zqorat_A_2147725667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Zqorat.A"
        threat_id = "2147725667"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zqorat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "\\ZRAT\\QRAT" ascii //weight: 8
        $x_10_2 = "\\QRAT_Client\\PluginInterface\\" ascii //weight: 10
        $x_2_3 = "\\ClientPluginInterface.pdb" ascii //weight: 2
        $x_1_4 = "AddToStartupFailed" ascii //weight: 1
        $x_1_5 = "DeleteKeyloggerLogs" ascii //weight: 1
        $x_1_6 = "DoAskElevate" ascii //weight: 1
        $x_1_7 = "DoCheckUploadTool" ascii //weight: 1
        $x_1_8 = "DoCheckUploadToolResponse" ascii //weight: 1
        $x_1_9 = "DoClientDisconnect" ascii //weight: 1
        $x_1_10 = "DoClientReconnect" ascii //weight: 1
        $x_1_11 = "DoClientUninstall" ascii //weight: 1
        $x_1_12 = "DoClientUpdate" ascii //weight: 1
        $x_1_13 = "DoDemand" ascii //weight: 1
        $x_1_14 = "DoesWin32MethodExist" ascii //weight: 1
        $x_1_15 = "DoExternalToolStart" ascii //weight: 1
        $x_1_16 = "DoExternalToolStartResponse" ascii //weight: 1
        $x_1_17 = "DoExternalToolStop" ascii //weight: 1
        $x_1_18 = "DoKeyboardEvent" ascii //weight: 1
        $x_1_19 = "DoRunUploadTool" ascii //weight: 1
        $x_1_20 = "DoSendUploadConfig" ascii //weight: 1
        $x_1_21 = "DoShutdownAction" ascii //weight: 1
        $x_1_22 = "DoUploadFile" ascii //weight: 1
        $x_1_23 = "DoVisitWebsite" ascii //weight: 1
        $x_1_24 = "GetInstalledApp" ascii //weight: 1
        $x_1_25 = "GetKeyloggerLogs" ascii //weight: 1
        $x_1_26 = "HandleInstallPacket" ascii //weight: 1
        $x_1_27 = "IsMouseKeyDown" ascii //weight: 1
        $x_1_28 = "IsMouseKeyUp" ascii //weight: 1
        $x_1_29 = "virtualKeyCode" ascii //weight: 1
        $x_1_30 = "VistaOrHigher" ascii //weight: 1
        $x_1_31 = "XpOrHigher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((20 of ($x_1_*))) or
            ((1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_8_*) and 12 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

