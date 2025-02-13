rule Trojan_MSIL_MassKeyLoader_2147771173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassKeyLoader!MTB"
        threat_id = "2147771173"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassKeyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "CryptoStream" ascii //weight: 1
        $x_1_3 = "AppDomain" ascii //weight: 1
        $x_1_4 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "ReadAllBytes" ascii //weight: 1
        $x_1_7 = "WriteAllBytes" ascii //weight: 1
        $x_1_8 = "AssemblyBuilderAccess" ascii //weight: 1
        $x_1_9 = "CreateProcess" ascii //weight: 1
        $x_1_10 = "GetProcAddress" ascii //weight: 1
        $x_1_11 = "System.Reflection.Emit" ascii //weight: 1
        $x_1_12 = "WebClient" ascii //weight: 1
        $x_1_13 = "get_EntryPoint" ascii //weight: 1
        $x_1_14 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_15 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_16 = "VirtualAllocEx" ascii //weight: 1
        $x_1_17 = "Mutex" ascii //weight: 1
        $x_1_18 = "set_Key" ascii //weight: 1
        $x_1_19 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_20 = "ReadProcessMemory" ascii //weight: 1
        $x_1_21 = "WriteProcessMemory" ascii //weight: 1
        $x_1_22 = "GetRuntimeDirectory" ascii //weight: 1
        $x_1_23 = "set_InitialDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

