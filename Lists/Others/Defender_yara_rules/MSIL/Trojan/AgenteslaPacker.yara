rule Trojan_MSIL_AgenteslaPacker_2147780085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgenteslaPacker!MTB"
        threat_id = "2147780085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgenteslaPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "get_AllowDrop" ascii //weight: 1
        $x_1_3 = "set_AllowDrop" ascii //weight: 1
        $x_1_4 = {00 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 00}  //weight: 1, accuracy: High
        $x_1_7 = "<PrivateImplementationDetails>" ascii //weight: 1
        $x_1_8 = "System.Threading" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AgenteslaPacker_2147780085_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgenteslaPacker!MTB"
        threat_id = "2147780085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgenteslaPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "AssemblyLoader" ascii //weight: 1
        $x_1_3 = "Costura" ascii //weight: 1
        $x_1_4 = "System.Threading" ascii //weight: 1
        $x_1_5 = "System.IO.Compression" ascii //weight: 1
        $x_1_6 = "ReadFromEmbeddedResources" ascii //weight: 1
        $x_1_7 = "requestedAssemblyName" ascii //weight: 1
        $x_1_8 = "CatchAndThrowEx:" wide //weight: 1
        $x_1_9 = "Didide by zero error" wide //weight: 1
        $x_1_10 = "DoStuff2:" wide //weight: 1
        $x_1_11 = "Inner exception:" wide //weight: 1
        $x_1_12 = "costura.classlibrary.dll.compressed" wide //weight: 1
        $x_1_13 = "costura.costura.dll.compressed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

