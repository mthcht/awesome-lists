rule Trojan_MSIL_FormBookInjector_2147760284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FormBookInjector!MTB"
        threat_id = "2147760284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBookInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "ProcessStartInfo" ascii //weight: 1
        $x_1_4 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_5 = "GetFileAttributes" ascii //weight: 1
        $x_1_6 = "GetProcAddress" ascii //weight: 1
        $x_1_7 = "GetUserName" ascii //weight: 1
        $x_1_8 = "CreateProcess" ascii //weight: 1
        $x_1_9 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_10 = "SetThreadContext" ascii //weight: 1
        $x_1_11 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_12 = "ReadProcessMemory" ascii //weight: 1
        $x_1_13 = "WriteProcessMemory" ascii //weight: 1
        $x_1_14 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_15 = "VirtualAllocEx" ascii //weight: 1
        $x_1_16 = "ResumeThread" ascii //weight: 1
        $x_1_17 = "get_CurrentThread" ascii //weight: 1
        $x_1_18 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_19 = "GetProcesses" ascii //weight: 1
        $x_1_20 = "set_WindowStyle" ascii //weight: 1
        $x_1_21 = "GetTempPath" ascii //weight: 1
        $x_1_22 = "DownloadFile" ascii //weight: 1
        $x_1_23 = "Invoke" ascii //weight: 1
        $x_1_24 = "GetProcessById" ascii //weight: 1
        $x_1_25 = "GetFolderPath" ascii //weight: 1
        $x_1_26 = "get_EntryPoint" ascii //weight: 1
        $x_1_27 = "GetParameters" ascii //weight: 1
        $x_1_28 = "GetRuntimeDirectory" ascii //weight: 1
        $x_1_29 = "IsInRole" ascii //weight: 1
        $x_1_30 = "CreateSubKey" ascii //weight: 1
        $x_1_31 = "SetValue" ascii //weight: 1
        $x_1_32 = "set_FileName" ascii //weight: 1
        $x_1_33 = "set_Arguments" ascii //weight: 1
        $x_1_34 = "set_UseShellExecute" ascii //weight: 1
        $x_1_35 = "set_RedirectStandardOutput" ascii //weight: 1
        $x_1_36 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_37 = "set_StartInfo" ascii //weight: 1
        $x_1_38 = "get_StandardOutput" ascii //weight: 1
        $x_1_39 = "ReadLine" ascii //weight: 1
        $x_1_40 = "get_EndOfStream" ascii //weight: 1
        $x_1_41 = "Append" ascii //weight: 1
        $x_1_42 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_43 = "set_Position" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

