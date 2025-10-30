rule HackTool_MSIL_FrostyStash_A_2147932410_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/FrostyStash.A!dha"
        threat_id = "2147932410"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FrostyStash"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "U4OgFs2opxnHKUUwf280DvUGxewgqlBJKzHZpWhg8NPr2Af0D9" wide //weight: 10
        $x_1_2 = "system_data_size" wide //weight: 1
        $x_1_3 = "time_scale" wide //weight: 1
        $x_1_4 = "interval_engine" wide //weight: 1
        $x_1_5 = "internal_id" wide //weight: 1
        $x_1_6 = "internal_key" wide //weight: 1
        $x_1_7 = "rate_control" wide //weight: 1
        $x_1_8 = "span_min" wide //weight: 1
        $x_1_9 = "span_max" wide //weight: 1
        $x_1_10 = "days_not_work" wide //weight: 1
        $x_1_11 = "TMR_Engine" ascii //weight: 1
        $x_1_12 = "TMR_CheckEvent" ascii //weight: 1
        $x_1_13 = "TMR_KeepAlive" ascii //weight: 1
        $x_1_14 = "TMR_GenKeys" ascii //weight: 1
        $x_1_15 = "TMR_CheckDB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule HackTool_MSIL_FrostyStash_B_2147932628_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/FrostyStash.B!dha"
        threat_id = "2147932628"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FrostyStash"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MessageData" wide //weight: 1
        $x_1_2 = "TypeData" wide //weight: 1
        $x_1_3 = "PackageData" wide //weight: 1
        $x_1_4 = "StatusConnection" wide //weight: 1
        $x_1_5 = "END_OF_MESSAGES" wide //weight: 1
        $x_1_6 = "NO_MESSAGES" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_FrostyStash_C_2147932629_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/FrostyStash.C!dha"
        threat_id = "2147932629"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FrostyStash"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_uniqIdSys" ascii //weight: 1
        $x_1_2 = "_uniqIdCor" ascii //weight: 1
        $x_1_3 = "ProcessData" ascii //weight: 1
        $x_1_4 = "_pathLog" ascii //weight: 1
        $x_1_5 = "get_Msg" ascii //weight: 1
        $x_1_6 = "JavaScriptSerializer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_FrostyStash_AA_2147956418_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/FrostyStash.AA!dha"
        threat_id = "2147956418"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FrostyStash"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TMR_Engine" ascii //weight: 1
        $x_1_2 = "TMR_KeepAlive" ascii //weight: 1
        $x_1_3 = "TMR_PingSystem" ascii //weight: 1
        $x_1_4 = "TMR_PingNet" ascii //weight: 1
        $x_1_5 = "TMR_CheckEvent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_FrostyStash_BA_2147956419_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/FrostyStash.BA!dha"
        threat_id = "2147956419"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FrostyStash"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WebSocketSharp" ascii //weight: 1
        $x_1_2 = "v4.0.30319" ascii //weight: 1
        $x_1_3 = "CancellationToken" ascii //weight: 1
        $x_1_4 = "JavaScriptSerializer" ascii //weight: 1
        $x_1_5 = "619cb2b1-9401-4025-8b83-b8fd42d9a1a1" ascii //weight: 1
        $x_1_6 = "Microsoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii //weight: 1
        $x_1_7 = "SMNet.Form1.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_FrostyStash_F_2147956420_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/FrostyStash.F!dha"
        threat_id = "2147956420"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FrostyStash"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kill" ascii //weight: 1
        $x_1_2 = "get_ModuleVersionId" ascii //weight: 1
        $x_1_3 = "get_Message" ascii //weight: 1
        $x_1_4 = "get_UserName" ascii //weight: 1
        $x_1_5 = "get_ProcessName" ascii //weight: 1
        $x_1_6 = "get_FullName" ascii //weight: 1
        $x_1_7 = "set_ClientSize" ascii //weight: 1
        $x_1_8 = "JavaScriptSerializer" ascii //weight: 1
        $x_1_9 = "GetProcesses" ascii //weight: 1
        $x_1_10 = "set_UseShellExecute" ascii //weight: 1
        $x_1_11 = "get_Png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

