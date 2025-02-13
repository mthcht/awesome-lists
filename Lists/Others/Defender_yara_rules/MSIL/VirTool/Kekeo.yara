rule VirTool_MSIL_Kekeo_NT_2147817920_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Kekeo.NT!MTB"
        threat_id = "2147817920"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kekeo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$658c8b7f-3664-4a95-9572-a3e5871dfc06" ascii //weight: 10
        $x_10_2 = "$bf00b581-a6ce-489f-91a5-7090eb9673cd" ascii //weight: 10
        $x_10_3 = "$bd5220f7-e1fb-41d2-91ec-e4c50c6e9b9f" ascii //weight: 10
        $x_10_4 = "$657c8b7f-3664-4a95-9572-a3e5871dfc06" ascii //weight: 10
        $x_10_5 = "$c40aaf10-9d06-412a-b04a-a51ce5e54449" ascii //weight: 10
        $x_10_6 = "$2b07b501-43ba-4a43-94dc-551d685c129b" ascii //weight: 10
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_11 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

