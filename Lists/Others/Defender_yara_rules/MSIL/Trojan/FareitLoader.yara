rule Trojan_MSIL_FareitLoader_2147768090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FareitLoader!MTB"
        threat_id = "2147768090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FareitLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "719"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetFileNameWithoutExtension" ascii //weight: 1
        $x_1_2 = "System.IO.Compression" ascii //weight: 1
        $x_1_3 = "GetEntryAssembly" ascii //weight: 1
        $x_1_4 = "project_name" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "BitConverter" ascii //weight: 1
        $x_1_7 = "System.Threading" ascii //weight: 1
        $x_1_8 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_9 = "System.Runtime.Remoting" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_1_11 = "FileStream" ascii //weight: 1
        $x_1_12 = "FileMode" ascii //weight: 1
        $x_1_13 = "FileAccess" ascii //weight: 1
        $x_1_14 = "FileShare" ascii //weight: 1
        $x_1_15 = "set_Key" ascii //weight: 1
        $x_1_16 = "set_IV" ascii //weight: 1
        $x_1_17 = "CreateDecryptor" ascii //weight: 1
        $x_1_18 = "FlushFinalBlock" ascii //weight: 1
        $x_1_19 = "ToBase64String" ascii //weight: 1
        $x_50_20 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 50
        $x_50_21 = "{11111-22222-10009-11112}" wide //weight: 50
        $x_50_22 = "{11111-22222-50001-00000}" wide //weight: 50
        $x_50_23 = "GetDelegateForFunctionPointer" wide //weight: 50
        $x_50_24 = "file:///" wide //weight: 50
        $x_50_25 = "Location" wide //weight: 50
        $x_50_26 = "{11111-22222-20001-00001}" wide //weight: 50
        $x_50_27 = "{11111-22222-20001-00002}" wide //weight: 50
        $x_50_28 = "{11111-22222-30001-00001}" wide //weight: 50
        $x_50_29 = "{11111-22222-30001-00002}" wide //weight: 50
        $x_50_30 = "{11111-22222-40001-00001}" wide //weight: 50
        $x_50_31 = "{11111-22222-40001-00002}" wide //weight: 50
        $x_50_32 = "{11111-22222-50001-00001}" wide //weight: 50
        $x_50_33 = "{11111-22222-50001-00002}" wide //weight: 50
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

