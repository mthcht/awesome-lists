rule PWS_MSIL_Agentesla_2147754637_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Agentesla!MTB"
        threat_id = "2147754637"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agentesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ModelsCore" wide //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_4 = "SnakeBOT" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "ModelsCore.Properties.Resources" ascii //weight: 1
        $x_1_7 = "FF645E0EC493CB6CFFA5B2FFA15486705589ABFEBD845F753AA9A47B2B1491E7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

