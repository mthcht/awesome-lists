rule Backdoor_MSIL_CobaltStrikeLoader_F_2147781186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/CobaltStrikeLoader.F!MTB"
        threat_id = "2147781186"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Schedule.Service" wide //weight: 1
        $x_1_2 = "Connect" wide //weight: 1
        $x_1_3 = "GetFolder" wide //weight: 1
        $x_1_4 = "GetTasks" wide //weight: 1
        $x_1_5 = "Hidden" wide //weight: 1
        $x_1_6 = "DisallowStartIfOnBatteries" wide //weight: 1
        $x_1_7 = "RunOnlyIfNetworkAvailable" wide //weight: 1
        $x_1_8 = "StartWhenAvailable" wide //weight: 1
        $x_1_9 = "LogonType" wide //weight: 1
        $x_1_10 = "RegisterTaskDefinition" wide //weight: 1
        $x_1_11 = "DeleteTask" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

