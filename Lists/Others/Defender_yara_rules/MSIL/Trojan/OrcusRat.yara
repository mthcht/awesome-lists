rule Trojan_MSIL_Orcusrat_ADN_2147779929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Orcusrat.ADN!MTB"
        threat_id = "2147779929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Orcusrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "OrcUS" ascii //weight: 5
        $x_5_2 = "OrcUS.Watchdog" ascii //weight: 5
        $x_4_3 = "KillButton_Click" ascii //weight: 4
        $x_4_4 = "gET_RemoteEndPoint" ascii //weight: 4
        $x_4_5 = "DisableInstallationPrompt" ascii //weight: 4
        $x_4_6 = "gET_kEYLoggerService" ascii //weight: 4
        $x_4_7 = "gET_ServerConnection" ascii //weight: 4
        $x_4_8 = "gET_RequireAdministratorPrivileges" ascii //weight: 4
        $x_4_9 = "gETFreeTempFileName" ascii //weight: 4
        $x_4_10 = "gET_TaskName" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_4_*))) or
            ((1 of ($x_5_*) and 5 of ($x_4_*))) or
            ((2 of ($x_5_*) and 4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Orcusrat_ADT_2147779931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Orcusrat.ADT!MTB"
        threat_id = "2147779931"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Orcusrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Orcus" ascii //weight: 4
        $x_4_2 = "KillButton_Click" ascii //weight: 4
        $x_4_3 = "get_KeyLoggerService" ascii //weight: 4
        $x_4_4 = "TakeScreenshot" ascii //weight: 4
        $x_4_5 = "_keyboardHookHandle" ascii //weight: 4
        $x_3_6 = "get_IcmpSockets" ascii //weight: 3
        $x_3_7 = "IsATcpAnaylzerRunning" ascii //weight: 3
        $x_3_8 = "set_AntiVMs" ascii //weight: 3
        $x_3_9 = "set_AntiDebugger" ascii //weight: 3
        $x_3_10 = "set_TaskSchedulerTaskName" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_3_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

