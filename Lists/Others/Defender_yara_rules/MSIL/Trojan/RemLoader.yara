rule Trojan_MSIL_RemLoader_2147760285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader!MTB"
        threat_id = "2147760285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cyrus.exe" ascii //weight: 1
        $x_1_2 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "ProcessStartInfo" ascii //weight: 1
        $x_1_5 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "System.Security.AccessControl" ascii //weight: 1
        $x_1_8 = "ThreadStart" ascii //weight: 1
        $x_1_9 = "CreateApi" ascii //weight: 1
        $x_1_10 = "SetAccessRuleProtection" ascii //weight: 1
        $x_1_11 = "get_UserName" ascii //weight: 1
        $x_1_12 = "set_WindowStyle" ascii //weight: 1
        $x_1_13 = "DownloadFile" ascii //weight: 1
        $x_1_14 = "GetRuntimeDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemLoader_2147760285_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader!MTB"
        threat_id = "2147760285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_2 = "OutputDebugString" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "ResolveEventArgs" ascii //weight: 1
        $x_1_5 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_6 = "NtQueryInformationProcess" ascii //weight: 1
        $x_1_7 = "System.Threading" ascii //weight: 1
        $x_1_8 = "CreateProcess" ascii //weight: 1
        $x_1_9 = "GetThreadContext" ascii //weight: 1
        $x_1_10 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_11 = "SetThreadContext" ascii //weight: 1
        $x_1_12 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_13 = "ReadProcessMemory" ascii //weight: 1
        $x_1_14 = "WriteProcessMemory" ascii //weight: 1
        $x_1_15 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_16 = "VirtualAllocEx" ascii //weight: 1
        $x_1_17 = "ResumeThread" ascii //weight: 1
        $x_1_18 = "AppDomain" ascii //weight: 1
        $x_1_19 = "get_CurrentDomain" ascii //weight: 1
        $x_1_20 = "WebClient" ascii //weight: 1
        $x_1_21 = "System.Net" ascii //weight: 1
        $x_1_22 = "GetTempPath" ascii //weight: 1
        $x_1_23 = "DownloadFile" ascii //weight: 1
        $x_1_24 = "Kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemLoader_2147760285_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader!MTB"
        threat_id = "2147760285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.IO" ascii //weight: 1
        $x_1_2 = "BitmapData" ascii //weight: 1
        $x_1_3 = "OverrideMetadata" ascii //weight: 1
        $x_1_4 = "get_CurrentThread" ascii //weight: 1
        $x_1_5 = "TotalBytesTransferred" ascii //weight: 1
        $x_1_6 = "StreamBytesTransferred" ascii //weight: 1
        $x_1_7 = "GetProcessesByName" ascii //weight: 1
        $x_1_8 = "GetCommandLineArgs" ascii //weight: 1
        $x_1_9 = "DefinePInvokeMethod" ascii //weight: 1
        $x_1_10 = "GetRandomFileName" ascii //weight: 1
        $x_1_11 = "GetRuntimeDirectory" ascii //weight: 1
        $x_1_12 = "set_WindowStyle" ascii //weight: 1
        $x_1_13 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_14 = "set_FileName" ascii //weight: 1
        $x_1_15 = "set_Arguments" ascii //weight: 1
        $x_1_16 = "GetProcesses" ascii //weight: 1
        $x_1_17 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_18 = "set_UseShellExecute" ascii //weight: 1
        $x_1_19 = "set_RedirectStandardError" ascii //weight: 1
        $x_1_20 = "set_RedirectStandardInput" ascii //weight: 1
        $x_1_21 = "get_CurrentDomain" ascii //weight: 1
        $x_1_22 = "DefaultStyleKeyProperty" ascii //weight: 1
        $x_1_23 = "GetCurrentProcess" ascii //weight: 1
        $x_1_24 = "ContainsKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemLoader_2147760285_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader!MTB"
        threat_id = "2147760285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PROCESS_SET_QUOTA" ascii //weight: 1
        $x_1_2 = "WRITE_DAC" ascii //weight: 1
        $x_1_3 = "PROCESS_CREATE_THREAD" ascii //weight: 1
        $x_1_4 = "PROCESS_VM_READ" ascii //weight: 1
        $x_1_5 = "STANDARD_RIGHTS_REQUIRED" ascii //weight: 1
        $x_1_6 = "PROCESS_DUP_HANDLE" ascii //weight: 1
        $x_1_7 = "PROCESS_SUSPEND_RESUME" ascii //weight: 1
        $x_1_8 = "PROCESS_TERMINATE" ascii //weight: 1
        $x_1_9 = "IMPERSONATE" ascii //weight: 1
        $x_1_10 = "PROCESS_VM_WRITE" ascii //weight: 1
        $x_1_11 = "SYNCHRONIZE" ascii //weight: 1
        $x_1_12 = "READ_CONTROL" ascii //weight: 1
        $x_1_13 = "ProcessUserModeIOPL" ascii //weight: 1
        $x_1_14 = "SET_THREAD_TOKEN" ascii //weight: 1
        $x_1_15 = "PROCESS_QUERY_LIMITED_INFORMATION" ascii //weight: 1
        $x_1_16 = "SYSTEM_KERNEL_DEBUGGER_INFORMATION" ascii //weight: 1
        $x_1_17 = "PROCESS_SET_INFORMATION" ascii //weight: 1
        $x_1_18 = "PROCESS_QUERY_INFORMATION" ascii //weight: 1
        $x_1_19 = "DIRECT_IMPERSONATION" ascii //weight: 1
        $x_1_20 = "PROCESS_VM_OPERATION" ascii //weight: 1
        $x_1_21 = "ITE_OWNER" ascii //weight: 1
        $x_1_22 = "PROCESSINFOCLASS" ascii //weight: 1
        $x_1_23 = "SYSTEM_INFORMATION_CLASS" ascii //weight: 1
        $x_1_24 = "PROCESS_ALL_ACCESS" ascii //weight: 1
        $x_1_25 = "PROCESS_CREATE_PROCESS" ascii //weight: 1
        $x_1_26 = "GET_CONTEXT" ascii //weight: 1
        $x_1_27 = "SET_CONTEXT" ascii //weight: 1
        $x_30_28 = "INJECT_HERE" wide //weight: 30
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 20 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_RemLoader_2147760285_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader!MTB"
        threat_id = "2147760285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_2 = "OutputDebugString" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "System.Threading" ascii //weight: 1
        $x_1_5 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_6 = "NtQueryInformationProcess" ascii //weight: 1
        $x_1_7 = "CreateProcess" ascii //weight: 1
        $x_1_8 = "GetThreadContext" ascii //weight: 1
        $x_1_9 = "SetThreadContext" ascii //weight: 1
        $x_1_10 = "ReadProcessMemory" ascii //weight: 1
        $x_1_11 = "WriteProcessMemory" ascii //weight: 1
        $x_1_12 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_13 = "WebClient" ascii //weight: 1
        $x_1_14 = "RegistryKeyPermissionCheck" ascii //weight: 1
        $x_1_15 = "get_ProcessName" ascii //weight: 1
        $x_1_16 = "get_CurrentThread" ascii //weight: 1
        $x_1_17 = "get_IsAttached" ascii //weight: 1
        $x_1_18 = "IsLogging" ascii //weight: 1
        $x_1_19 = "AppDomain" ascii //weight: 1
        $x_1_20 = "get_CurrentDomain" ascii //weight: 1
        $x_1_21 = "GetProcessById" ascii //weight: 1
        $x_1_22 = "CreateSubKey" ascii //weight: 1
        $x_1_23 = "SetValue" ascii //weight: 1
        $x_1_24 = "set_FileName" ascii //weight: 1
        $x_1_25 = "set_Arguments" ascii //weight: 1
        $x_1_26 = "set_UseShellExecute" ascii //weight: 1
        $x_1_27 = "set_RedirectStandardOutput" ascii //weight: 1
        $x_1_28 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_29 = "set_StartInfo" ascii //weight: 1
        $x_1_30 = "get_StandardOutput" ascii //weight: 1
        $x_1_31 = "ReadLine" ascii //weight: 1
        $x_1_32 = "get_EndOfStream" ascii //weight: 1
        $x_1_33 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemLoader_2147760285_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader!MTB"
        threat_id = "2147760285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_5 = "NtQueryInformationProcess" ascii //weight: 1
        $x_1_6 = "System.Threading" ascii //weight: 1
        $x_1_7 = "CreateProcess" ascii //weight: 1
        $x_1_8 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_9 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_10 = "ReadProcessMemory" ascii //weight: 1
        $x_1_11 = "WriteProcessMemory" ascii //weight: 1
        $x_1_12 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_13 = "VirtualAllocEx" ascii //weight: 1
        $x_1_14 = "ResumeThread" ascii //weight: 1
        $x_1_15 = "DebuggableAttribute" ascii //weight: 1
        $x_1_16 = "get_ProcessName" ascii //weight: 1
        $x_1_17 = "ParameterizedThreadStart" ascii //weight: 1
        $x_1_18 = "set_IsBackground" ascii //weight: 1
        $x_1_19 = "IsLogging" ascii //weight: 1
        $x_1_20 = "GetCurrentProcess" ascii //weight: 1
        $x_1_21 = "get_Size" ascii //weight: 1
        $x_1_22 = "get_IsAttached" ascii //weight: 1
        $x_1_23 = "get_CurrentThread" ascii //weight: 1
        $x_1_24 = "get_IsAlive" ascii //weight: 1
        $x_1_25 = "AppDomain" ascii //weight: 1
        $x_1_26 = "get_CurrentDomain" ascii //weight: 1
        $x_1_27 = "set_WindowStyle" ascii //weight: 1
        $x_1_28 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_29 = "WebClient" ascii //weight: 1
        $x_1_30 = "DownloadFile" ascii //weight: 1
        $x_1_31 = "get_EntryPoint" ascii //weight: 1
        $x_1_32 = "GetRuntimeDirectory" ascii //weight: 1
        $x_1_33 = "KeyNotFoundException" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemLoader_2147760285_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader!MTB"
        threat_id = "2147760285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "165"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{11111-22222-10009-11112}" wide //weight: 1
        $x_1_2 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_3 = "{11111-22222-20001-00001}" wide //weight: 1
        $x_1_4 = "{11111-22222-20001-00002}" wide //weight: 1
        $x_1_5 = "{11111-22222-30001-00001}" wide //weight: 1
        $x_1_6 = "{11111-22222-30001-00002}" wide //weight: 1
        $x_1_7 = "{11111-22222-40001-00001}" wide //weight: 1
        $x_1_8 = "{11111-22222-40001-00002}" wide //weight: 1
        $x_10_9 = "file:///" wide //weight: 10
        $x_10_10 = "AppDomain" ascii //weight: 10
        $x_10_11 = "get_CurrentDomain" ascii //weight: 10
        $x_10_12 = "Activator" ascii //weight: 10
        $x_10_13 = "CreateDecryptor" ascii //weight: 10
        $x_10_14 = "CreateEncryptor" ascii //weight: 10
        $x_10_15 = "Process" ascii //weight: 10
        $x_10_16 = "GetProcAddress" ascii //weight: 10
        $x_10_17 = "Wow64GetThreadContext" ascii //weight: 10
        $x_10_18 = "Wow64SetThreadContext" ascii //weight: 10
        $x_10_19 = "VirtualAllocEx" ascii //weight: 10
        $x_10_20 = "set_Key" ascii //weight: 10
        $x_10_21 = "System.Security.Cryptography" ascii //weight: 10
        $x_10_22 = "get_Assembly" ascii //weight: 10
        $x_10_23 = "ReadProcessMemory" ascii //weight: 10
        $x_10_24 = "WriteProcessMemory" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((16 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_RemLoader_2147760285_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader!MTB"
        threat_id = "2147760285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "131"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" wide //weight: 10
        $x_10_2 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 10
        $x_10_3 = "{11111-22222-10009-11112}" wide //weight: 10
        $x_10_4 = "{11111-22222-50001-00000}" wide //weight: 10
        $x_10_5 = "GetDelegateForFunctionPointer" wide //weight: 10
        $x_10_6 = "file:///" wide //weight: 10
        $x_10_7 = "Location" wide //weight: 10
        $x_10_8 = "{11111-22222-20001-00001}" wide //weight: 10
        $x_10_9 = "{11111-22222-20001-00002}" wide //weight: 10
        $x_10_10 = "{11111-22222-30001-00001}" wide //weight: 10
        $x_10_11 = "{11111-22222-30001-00002}" wide //weight: 10
        $x_10_12 = "{11111-22222-40001-00001}" wide //weight: 10
        $x_10_13 = "{11111-22222-40001-00002}" wide //weight: 10
        $x_1_14 = "Jupiter.dll" wide //weight: 1
        $x_1_15 = "Aphrodite.dll" wide //weight: 1
        $x_1_16 = "FixedPointy.dll" wide //weight: 1
        $x_1_17 = "FixedPointy.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((13 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_RemLoader_MBCL_2147843342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader.MBCL!MTB"
        threat_id = "2147843342"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 00 69 00 72 00 65 00 00 09 79 00 65 00 6e 00 6b 00 00 0b 7a 00 65 00 74 00 74 00 61}  //weight: 1, accuracy: High
        $x_1_2 = "$87fdd840-e571-4a98-b921-b4cc36fd2805" ascii //weight: 1
        $x_1_3 = "aDayAtTheRaces.Properties.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemLoader_RPX_2147846025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader.RPX!MTB"
        threat_id = "2147846025"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 06 5a 00 0e 00 3c 07 47 07 0a 00 67 07 a2 02 0a 00 82 07 a2 02 0a 00 97 07 a2 02 0a 00 c5 07 a2 02 06 00 f4 07 da 00 06 00}  //weight: 1, accuracy: High
        $x_1_2 = "Defune LS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemLoader_MBDF_2147847304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader.MBDF!MTB"
        threat_id = "2147847304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 02 06 28 ?? ?? 00 06 72 fa 3d 04 70 72 fe 3d 04 70 6f ?? 00 00 0a 72 02 3e 04 70 72 06 3e 04 70 6f ?? 00 00 0a 0a 06 72 0c 3e 04 70 72 10 3e 04 70 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16 1f 7e 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemLoader_NR_2147917176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader.NR!MTB"
        threat_id = "2147917176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 f1 0f 00 0a 6f 53 00 00 0a 07 1f 10 8d 84 00 00 01 25 d0 e0 0b 00 04 28 f1 0f 00 0a 6f 1d 10 00 0a 06 07 6f 55 00 00 0a 17 73 07 10 00 0a 0c 08 02 16 02 8e 69 6f 08 10 00 0a}  //weight: 5, accuracy: High
        $x_1_2 = "$877eda90-9a79-4fa2-a8f7-253748c489a2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemLoader_CZ_2147919281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemLoader.CZ!MTB"
        threat_id = "2147919281"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MAK5ID7H6SF8ADGGHJFKILOO" ascii //weight: 2
        $x_2_2 = "minelabfoto.My.Resources" ascii //weight: 2
        $x_2_3 = "ncoevPI0jgIx9kwtRB.9gVCUF2McRe8OCARus" ascii //weight: 2
        $x_1_4 = "1C4BFDD9-F7B3-4F42-AC3E-DC1CAE0984A6" ascii //weight: 1
        $x_1_5 = "jZ9TmyBE4Iv51Ew9jw" ascii //weight: 1
        $x_1_6 = "xSuCnIFm2UG4LTvByI" ascii //weight: 1
        $x_1_7 = "XUR6qj3NuBaZKZEh88" ascii //weight: 1
        $x_1_8 = "qrYEEQ5vCh6dvkNN3nG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

