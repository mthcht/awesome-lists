rule Trojan_MSIL_CrysenLoader_2147772069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrysenLoader!MTB"
        threat_id = "2147772069"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrysenLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetProcessById" ascii //weight: 1
        $x_1_2 = "ResumeThread" ascii //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_5 = "GetTempFileName" ascii //weight: 1
        $x_1_6 = "EditorBrowsableState" ascii //weight: 1
        $x_1_7 = "System.Threading" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "Kill" ascii //weight: 1
        $x_1_10 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_11 = "get_CurrentDomain" ascii //weight: 1
        $x_1_12 = "InvokeMember" ascii //weight: 1
        $x_1_13 = "CreateDecryptor" ascii //weight: 1
        $x_1_14 = "DebuggingModes" ascii //weight: 1
        $x_1_15 = "CreateProcess" ascii //weight: 1
        $x_1_16 = "System.Reflection.Emit" ascii //weight: 1
        $x_1_17 = "get_EntryPoint" ascii //weight: 1
        $x_1_18 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_19 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_20 = "ReadProcessMemory" ascii //weight: 1
        $x_1_21 = "WriteProcessMemory" ascii //weight: 1
        $x_1_22 = "dead codeT" ascii //weight: 1
        $x_1_23 = "StripAfterObfuscation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

