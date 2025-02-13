rule VirTool_MSIL_Utlaz_A_2147816167_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Utlaz.A!MTB"
        threat_id = "2147816167"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Utlaz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ImplantCommandsInit" ascii //weight: 1
        $x_1_2 = "PollImplant" ascii //weight: 1
        $x_1_3 = "ImplantTask" ascii //weight: 1
        $x_1_4 = "ExecuteAssemMethod" ascii //weight: 1
        $x_1_5 = "HTTPComms" ascii //weight: 1
        $x_1_6 = "ImplantDataUtils" ascii //weight: 1
        $x_1_7 = "CMDShell" ascii //weight: 1
        $x_1_8 = "PSShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Utlaz_C_2147816168_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Utlaz.C!MTB"
        threat_id = "2147816168"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Utlaz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_CurrentImplant" ascii //weight: 1
        $x_1_2 = "ImplantList" ascii //weight: 1
        $x_1_3 = ".Utils.ImplantUtils" ascii //weight: 1
        $x_1_4 = "Utils.ClientUtils" ascii //weight: 1
        $x_1_5 = "AtlasException" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

