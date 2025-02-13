rule VirTool_MSIL_BluntC2_C_2147793719_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/BluntC2.C!MTB"
        threat_id = "2147793719"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BluntC2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateEtwBypassHook" ascii //weight: 1
        $x_1_2 = "ExecuteShellCommand" ascii //weight: 1
        $x_1_3 = "SendC2Message" ascii //weight: 1
        $x_1_4 = "AmsiScanBufferDelegate" ascii //weight: 1
        $x_1_5 = "Pivoting" ascii //weight: 1
        $x_1_6 = "Evasion" ascii //weight: 1
        $x_1_7 = "Credentials" ascii //weight: 1
        $x_1_8 = "DInvoke.DynamicInvoke" ascii //weight: 1
        $x_1_9 = "DInvoke.Injection" ascii //weight: 1
        $x_1_10 = "DynamicInvocation.DynamicInvoke" ascii //weight: 1
        $x_1_11 = "DynamicInvocation.Injection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule VirTool_MSIL_BluntC2_J_2147843228_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/BluntC2.J!MTB"
        threat_id = "2147843228"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BluntC2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Commands.ExecuteAssembly" ascii //weight: 1
        $x_1_2 = ".Commands.MakeToken" ascii //weight: 1
        $x_1_3 = ".Messages" ascii //weight: 1
        $x_1_4 = "HandleReversePortForwardPacket" ascii //weight: 1
        $x_1_5 = "get_SpawnTo" ascii //weight: 1
        $x_1_6 = "ReversePortForwardState" ascii //weight: 1
        $x_1_7 = "DroneCommand" ascii //weight: 1
        $x_1_8 = ".Commands.StealToken" ascii //weight: 1
        $x_1_9 = ".Commands.Shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

