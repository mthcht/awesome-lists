rule Trojan_MSIL_MassLoader_2147771178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLoader!MTB"
        threat_id = "2147771178"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiSand" ascii //weight: 1
        $x_1_2 = "BinRes" ascii //weight: 1
        $x_1_3 = "Res3bin" ascii //weight: 1
        $x_1_4 = "CreateProcess" ascii //weight: 1
        $x_1_5 = "GetThreadContext" ascii //weight: 1
        $x_1_6 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_7 = "SetThreadContext" ascii //weight: 1
        $x_1_8 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_9 = "ReadProcessMemory" ascii //weight: 1
        $x_1_10 = "WriteProcessMemory" ascii //weight: 1
        $x_1_11 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_12 = "VirtualAllocEx" ascii //weight: 1
        $x_1_13 = "ResumeThread" ascii //weight: 1
        $x_1_14 = "FromBase64String" ascii //weight: 1
        $x_1_15 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_16 = "CreateDecryptor" ascii //weight: 1
        $x_1_17 = "CreateEncryptor" ascii //weight: 1
        $x_1_18 = "ToBase64String" ascii //weight: 1
        $x_1_19 = "Kill" ascii //weight: 1
        $x_1_20 = "Shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLoader_2147771178_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLoader!MTB"
        threat_id = "2147771178"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiSand" ascii //weight: 1
        $x_1_2 = "BinRes" ascii //weight: 1
        $x_1_3 = "Res3bin" ascii //weight: 1
        $x_1_4 = "CreateProcess" ascii //weight: 1
        $x_1_5 = "GetThreadContext" ascii //weight: 1
        $x_1_6 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_7 = "SetThreadContext" ascii //weight: 1
        $x_1_8 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_9 = "ReadProcessMemory" ascii //weight: 1
        $x_1_10 = "WriteProcessMemory" ascii //weight: 1
        $x_1_11 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_12 = "VirtualAllocEx" ascii //weight: 1
        $x_1_13 = "ResumeThread" ascii //weight: 1
        $x_1_14 = "FromBase64String" ascii //weight: 1
        $x_1_15 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_16 = "CreateDecryptor" ascii //weight: 1
        $x_1_17 = "CreateEncryptor" ascii //weight: 1
        $x_1_18 = "ToBase64String" ascii //weight: 1
        $x_1_19 = "Kill" ascii //weight: 1
        $x_1_20 = "Shell" ascii //weight: 1
        $x_1_21 = "{11111-22222-10009-11112}" wide //weight: 1
        $x_1_22 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_23 = "GetDelegateForFunctionPointer" wide //weight: 1
        $x_1_24 = "file:///" wide //weight: 1
        $x_1_25 = "Location" wide //weight: 1
        $x_1_26 = "Find" wide //weight: 1
        $x_1_27 = "ResourceA" wide //weight: 1
        $x_1_28 = "Virtual" wide //weight: 1
        $x_1_29 = "Alloc" wide //weight: 1
        $x_1_30 = "Write" wide //weight: 1
        $x_1_31 = "Process" wide //weight: 1
        $x_1_32 = "Memory" wide //weight: 1
        $x_1_33 = "Protect" wide //weight: 1
        $x_1_34 = "Open" wide //weight: 1
        $x_1_35 = "Close" wide //weight: 1
        $x_1_36 = "Handle" wide //weight: 1
        $x_1_37 = "kernel" wide //weight: 1
        $x_1_38 = "32.dll" wide //weight: 1
        $x_1_39 = "{11111-22222-20001-00001}" wide //weight: 1
        $x_1_40 = "{11111-22222-20001-00002}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

