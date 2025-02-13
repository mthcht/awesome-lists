rule VirTool_MSIL_NetInject_A_2147692861_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/NetInject.A"
        threat_id = "2147692861"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WriteProcessMemory" ascii //weight: 10
        $x_10_2 = "SetThreadContext" ascii //weight: 10
        $x_10_3 = "ResumeThread" ascii //weight: 10
        $x_10_4 = "VirtualAllocEx" ascii //weight: 10
        $x_1_5 = "IsSandboxie" ascii //weight: 1
        $x_1_6 = "IsNormanSandbox" ascii //weight: 1
        $x_1_7 = "IsSunbeltSandbox" ascii //weight: 1
        $x_1_8 = "IsAnubisSandbox" ascii //weight: 1
        $x_1_9 = "IsCWSandbox" ascii //weight: 1
        $x_1_10 = "IsWireshark" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_NetInject_B_2147694943_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/NetInject.B"
        threat_id = "2147694943"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 85 02 a0 60 e8 ?? ?? ff ff 68 84 2a ab 54 50 e8 ?? ?? ff ff ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_NetInject_B_2147694943_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/NetInject.B"
        threat_id = "2147694943"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dgLoader" ascii //weight: 1
        $x_1_2 = "loader_array" ascii //weight: 1
        $x_1_3 = "GetDelegateForFunctionPointer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

