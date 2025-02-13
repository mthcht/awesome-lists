rule Trojan_MSIL_DarkStealerLoader_2147765437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkStealerLoader!MTB"
        threat_id = "2147765437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1319"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "<PrivateImplementationDetails>" ascii //weight: 1
        $x_1_3 = "res_name" ascii //weight: 1
        $x_1_4 = "proj_name" ascii //weight: 1
        $x_1_5 = "Buta" ascii //weight: 1
        $x_1_6 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_7 = "System.Reflection.Emit" ascii //weight: 1
        $x_1_8 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateDecryptor" ascii //weight: 1
        $x_1_11 = "ToBase64String" ascii //weight: 1
        $x_1_12 = "CreateEncryptor" ascii //weight: 1
        $x_1_13 = "HttpResponse" ascii //weight: 1
        $x_1_14 = "get_Width" ascii //weight: 1
        $x_1_15 = "get_Height" ascii //weight: 1
        $x_1_16 = "get_R" ascii //weight: 1
        $x_1_17 = "get_G" ascii //weight: 1
        $x_1_18 = "get_B" ascii //weight: 1
        $x_1_19 = "get_EntryPoint" ascii //weight: 1
        $x_50_20 = "{11111-22222-10009-11112}" wide //weight: 50
        $x_50_21 = "{11111-22222-50001-00000}" wide //weight: 50
        $x_50_22 = "GetDelegateForFunctionPointer" wide //weight: 50
        $x_50_23 = "file:///" wide //weight: 50
        $x_50_24 = "Location" wide //weight: 50
        $x_50_25 = "Find" wide //weight: 50
        $x_50_26 = "ResourceA" wide //weight: 50
        $x_50_27 = "Virtual" wide //weight: 50
        $x_50_28 = "Alloc" wide //weight: 50
        $x_50_29 = "Write" wide //weight: 50
        $x_50_30 = "Memory" wide //weight: 50
        $x_50_31 = "Protect" wide //weight: 50
        $x_50_32 = "Open" wide //weight: 50
        $x_50_33 = "Process" wide //weight: 50
        $x_50_34 = "Close" wide //weight: 50
        $x_50_35 = "Handle" wide //weight: 50
        $x_50_36 = "kernel" wide //weight: 50
        $x_50_37 = "32.dll" wide //weight: 50
        $x_50_38 = "{11111-22222-20001-00001}" wide //weight: 50
        $x_50_39 = "{11111-22222-20001-00002}" wide //weight: 50
        $x_50_40 = "{11111-22222-30001-00001}" wide //weight: 50
        $x_50_41 = "{11111-22222-30001-00002}" wide //weight: 50
        $x_50_42 = "{11111-22222-40001-00001}" wide //weight: 50
        $x_50_43 = "{11111-22222-40001-00002}" wide //weight: 50
        $x_50_44 = "{11111-22222-50001-00001}" wide //weight: 50
        $x_50_45 = "{11111-22222-50001-00002}" wide //weight: 50
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkStealerLoader_2147765437_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkStealerLoader!MTB"
        threat_id = "2147765437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "682"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppDomain" ascii //weight: 1
        $x_1_2 = "get_CurrentDomain" ascii //weight: 1
        $x_1_3 = "FileStream" ascii //weight: 1
        $x_1_4 = "FileMode" ascii //weight: 1
        $x_1_5 = "FileAccess" ascii //weight: 1
        $x_1_6 = "FileShare" ascii //weight: 1
        $x_1_7 = "Read" ascii //weight: 1
        $x_1_8 = "set_Key" ascii //weight: 1
        $x_1_9 = "set_IV" ascii //weight: 1
        $x_1_10 = "CreateDecryptor" ascii //weight: 1
        $x_1_11 = "CreateEncryptor" ascii //weight: 1
        $x_1_12 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_13 = "processInformation" ascii //weight: 1
        $x_1_14 = "currentDirectory" ascii //weight: 1
        $x_1_15 = "get_EntryPoint" ascii //weight: 1
        $x_1_16 = "get_UserName" ascii //weight: 1
        $x_1_17 = "Kill" ascii //weight: 1
        $x_1_18 = "GetProcessById" ascii //weight: 1
        $x_1_19 = "LoadLibraryA" ascii //weight: 1
        $x_1_20 = "GetTempFileName" ascii //weight: 1
        $x_1_21 = "AddAccessRule" ascii //weight: 1
        $x_1_22 = "SetAccessRuleProtection" ascii //weight: 1
        $x_1_23 = "ThreadStart" ascii //weight: 1
        $x_1_24 = "ProcessStartInfo" ascii //weight: 1
        $x_1_25 = "set_Arguments" ascii //weight: 1
        $x_1_26 = "set_UseShellExecute" ascii //weight: 1
        $x_1_27 = "set_WindowStyle" ascii //weight: 1
        $x_1_28 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_29 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_30 = "set_StartInfo" ascii //weight: 1
        $x_1_31 = "set_FileName" ascii //weight: 1
        $x_1_32 = "get_Control" ascii //weight: 1
        $x_50_33 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" wide //weight: 50
        $x_50_34 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 50
        $x_50_35 = "{11111-22222-10009-11112}" wide //weight: 50
        $x_50_36 = "{11111-22222-50001-00000}" wide //weight: 50
        $x_50_37 = "GetDelegateForFunctionPointer" wide //weight: 50
        $x_50_38 = "file:///" wide //weight: 50
        $x_50_39 = "Location" wide //weight: 50
        $x_50_40 = "{11111-22222-20001-00001}" wide //weight: 50
        $x_50_41 = "{11111-22222-20001-00002}" wide //weight: 50
        $x_50_42 = "{11111-22222-30001-00001}" wide //weight: 50
        $x_50_43 = "{11111-22222-30001-00002}" wide //weight: 50
        $x_50_44 = "{11111-22222-40001-00001}" wide //weight: 50
        $x_50_45 = "{11111-22222-40001-00002}" wide //weight: 50
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkStealerLoader_2147765437_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkStealerLoader!MTB"
        threat_id = "2147765437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "682"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppDomain" ascii //weight: 1
        $x_1_2 = "get_CurrentDomain" ascii //weight: 1
        $x_1_3 = "FileStream" ascii //weight: 1
        $x_1_4 = "FileMode" ascii //weight: 1
        $x_1_5 = "FileAccess" ascii //weight: 1
        $x_1_6 = "FileShare" ascii //weight: 1
        $x_1_7 = "set_Key" ascii //weight: 1
        $x_1_8 = "set_IV" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
        $x_1_10 = "CreateEncryptor" ascii //weight: 1
        $x_1_11 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_12 = "processInformation" ascii //weight: 1
        $x_1_13 = "currentDirectory" ascii //weight: 1
        $x_1_14 = "get_EntryPoint" ascii //weight: 1
        $x_1_15 = "get_UserName" ascii //weight: 1
        $x_1_16 = "GetProcessById" ascii //weight: 1
        $x_1_17 = "LoadLibraryA" ascii //weight: 1
        $x_1_18 = "GetTempFileName" ascii //weight: 1
        $x_1_19 = "AddAccessRule" ascii //weight: 1
        $x_1_20 = "SetAccessRuleProtection" ascii //weight: 1
        $x_1_21 = "ThreadStart" ascii //weight: 1
        $x_1_22 = "ProcessStartInfo" ascii //weight: 1
        $x_1_23 = "set_WindowStyle" ascii //weight: 1
        $x_1_24 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_25 = "get_Control" ascii //weight: 1
        $x_1_26 = "System.Security.AccessControl" ascii //weight: 1
        $x_1_27 = "FromBase64String" ascii //weight: 1
        $x_1_28 = "get_AllowOnlyFipsAlgorithms" ascii //weight: 1
        $x_1_29 = "ToBase64String" ascii //weight: 1
        $x_1_30 = "DownloadFile" ascii //weight: 1
        $x_1_31 = "FileSystemSecurity" ascii //weight: 1
        $x_1_32 = "Mutex" ascii //weight: 1
        $x_50_33 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" wide //weight: 50
        $x_50_34 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 50
        $x_50_35 = "{11111-22222-10009-11112}" wide //weight: 50
        $x_50_36 = "{11111-22222-50001-00000}" wide //weight: 50
        $x_50_37 = "GetDelegateForFunctionPointer" wide //weight: 50
        $x_50_38 = "file:///" wide //weight: 50
        $x_50_39 = "Location" wide //weight: 50
        $x_50_40 = "{11111-22222-20001-00001}" wide //weight: 50
        $x_50_41 = "{11111-22222-20001-00002}" wide //weight: 50
        $x_50_42 = "{11111-22222-30001-00001}" wide //weight: 50
        $x_50_43 = "{11111-22222-30001-00002}" wide //weight: 50
        $x_50_44 = "{11111-22222-40001-00001}" wide //weight: 50
        $x_50_45 = "{11111-22222-40001-00002}" wide //weight: 50
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

