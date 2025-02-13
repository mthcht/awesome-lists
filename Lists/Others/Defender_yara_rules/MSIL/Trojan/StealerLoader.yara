rule Trojan_MSIL_StealerLoader_2147772754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1ese92VWgsRJFT1srbgo5SFPIMk+jbLKTQ5ewNnKClI5csh6i5HItc6B40fr9wVIfYpUxb63Gvz4DGxgcD7qn2prJsnnb2tpZ+3zDqOUhcoTOoF0F7KDoLSLZDP3aQ5cAqh/bcGXWvQpfVDZoDC66W+BXEQw8VkWZAHPNKFE6WCHrFZSZRNnLmsFE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_2147772754_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VirtualProtect" ascii //weight: 1
        $x_1_2 = "ParameterizedThreadStart" ascii //weight: 1
        $x_1_3 = "FileStream" ascii //weight: 1
        $x_1_4 = "FileMode" ascii //weight: 1
        $x_1_5 = "FileAccess" ascii //weight: 1
        $x_1_6 = "FileShare" ascii //weight: 1
        $x_1_7 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_8 = "ServerComputer" ascii //weight: 1
        $x_1_9 = "HiddenStartup" ascii //weight: 1
        $x_1_10 = "HiddenStartupReg" ascii //weight: 1
        $x_1_11 = "InjectionHostIndex" ascii //weight: 1
        $x_1_12 = "Bitness" ascii //weight: 1
        $x_1_13 = "AntiVM" ascii //weight: 1
        $x_1_14 = "AntiSandBoxie" ascii //weight: 1
        $x_1_15 = "MeltedFileName" ascii //weight: 1
        $x_1_16 = "InjectionPersistence" ascii //weight: 1
        $x_1_17 = "StartupPersistence" ascii //weight: 1
        $x_1_18 = "WatchDogName" ascii //weight: 1
        $x_1_19 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_20 = "set_UseShellExecute" ascii //weight: 1
        $x_1_21 = "set_RedirectStandardError" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_2147772754_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mutex" ascii //weight: 1
        $x_1_2 = "System.Threading" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "ParseXmlDescription" ascii //weight: 1
        $x_1_5 = "checkifopen" ascii //weight: 1
        $x_1_6 = "mute" ascii //weight: 1
        $x_1_7 = "AllowAccess" ascii //weight: 1
        $x_1_8 = "ProtectTheFile" ascii //weight: 1
        $x_1_9 = "Sdownload" ascii //weight: 1
        $x_1_10 = "Durl" ascii //weight: 1
        $x_1_11 = "filerun" ascii //weight: 1
        $x_1_12 = "LoadLibraryA" ascii //weight: 1
        $x_1_13 = "payload" ascii //weight: 1
        $x_1_14 = "Fedree" ascii //weight: 1
        $x_1_15 = "GetInjectionPath" ascii //weight: 1
        $x_1_16 = "FileSystemAccessRule" ascii //weight: 1
        $x_1_17 = "WebClient" ascii //weight: 1
        $x_1_18 = "SetAccessRuleProtection" ascii //weight: 1
        $x_1_19 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_20 = "Kill" ascii //weight: 1
        $x_1_21 = "get_EntryPoint" ascii //weight: 1
        $x_1_22 = "get_R" ascii //weight: 1
        $x_1_23 = "get_G" ascii //weight: 1
        $x_1_24 = "get_B" ascii //weight: 1
        $x_1_25 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_26 = "get_BaseDirectory" ascii //weight: 1
        $x_1_27 = "LoadXml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (26 of ($x*))
}

rule Trojan_MSIL_StealerLoader_2147772754_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "ParameterizedThreadStart" ascii //weight: 1
        $x_1_4 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_5 = "NtQueryInformationProcess" ascii //weight: 1
        $x_1_6 = {44 41 44 00}  //weight: 1, accuracy: High
        $x_1_7 = {4d 4f 4d 00}  //weight: 1, accuracy: High
        $x_1_8 = "System.Data.SqlClient" ascii //weight: 1
        $x_1_9 = "System.IO.Compression" ascii //weight: 1
        $x_1_10 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_11 = "get_ProcessName" ascii //weight: 1
        $x_1_12 = "get_CurrentThread" ascii //weight: 1
        $x_1_13 = "get_IsAttached" ascii //weight: 1
        $x_1_14 = "GetCurrentProcess" ascii //weight: 1
        $x_1_15 = "get_CurrentDomain" ascii //weight: 1
        $x_1_16 = "get_Width" ascii //weight: 1
        $x_1_17 = "get_Height" ascii //weight: 1
        $x_1_18 = "EnableVisualStyles" ascii //weight: 1
        $x_1_19 = "SetCompatibleTextRenderingDefault" ascii //weight: 1
        $x_1_20 = "get_R" ascii //weight: 1
        $x_1_21 = "get_G" ascii //weight: 1
        $x_1_22 = "get_B" ascii //weight: 1
        $x_1_23 = "GetPixel" ascii //weight: 1
        $x_1_24 = "SetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_2147772754_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Data.SqlClient" ascii //weight: 1
        $x_1_2 = "Mutex" ascii //weight: 1
        $x_1_3 = "System.Threading" ascii //weight: 1
        $x_1_4 = "checkifopen" ascii //weight: 1
        $x_1_5 = "AllowAccess" ascii //weight: 1
        $x_1_6 = "ProtectTheFile" ascii //weight: 1
        $x_1_7 = "Sdownload" ascii //weight: 1
        $x_1_8 = "Durl" ascii //weight: 1
        $x_1_9 = "filerun" ascii //weight: 1
        $x_1_10 = "LoadLibraryA" ascii //weight: 1
        $x_1_11 = "GetProcAddress" ascii //weight: 1
        $x_1_12 = "payload" ascii //weight: 1
        $x_1_13 = "GetInjectionPath" ascii //weight: 1
        $x_1_14 = "ThreadStart" ascii //weight: 1
        $x_1_15 = "System.Security.AccessControl" ascii //weight: 1
        $x_1_16 = "FileSystemAccessRule" ascii //weight: 1
        $x_1_17 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_18 = "WebClient" ascii //weight: 1
        $x_1_19 = "commandLine" ascii //weight: 1
        $x_1_20 = "processInformation" ascii //weight: 1
        $x_1_21 = "ExecuteNonQuery" ascii //weight: 1
        $x_1_22 = "SetAccessRuleProtection" ascii //weight: 1
        $x_1_23 = "WriteAllText" ascii //weight: 1
        $x_1_24 = "set_WindowStyle" ascii //weight: 1
        $x_1_25 = "GetTempPath" ascii //weight: 1
        $x_1_26 = "DownloadFile" ascii //weight: 1
        $x_1_27 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_28 = "Kill" ascii //weight: 1
        $x_1_29 = "get_EntryPoint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_2147772754_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Reflection" ascii //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "Mutex" ascii //weight: 1
        $x_1_4 = "System.Threading" ascii //weight: 1
        $x_1_5 = "ProcessPersistence" ascii //weight: 1
        $x_1_6 = "AllowAccess" ascii //weight: 1
        $x_1_7 = "ProtectTheFile" ascii //weight: 1
        $x_1_8 = "Startup" ascii //weight: 1
        $x_1_9 = "CreateApi" ascii //weight: 1
        $x_1_10 = "StartInject" ascii //weight: 1
        $x_1_11 = "GetInjectionPath" ascii //weight: 1
        $x_1_12 = "FileSystemAccessRule" ascii //weight: 1
        $x_1_13 = "WebClient" ascii //weight: 1
        $x_1_14 = "DelegateWow64SetThreadContext" ascii //weight: 1
        $x_1_15 = "DelegateSetThreadContext" ascii //weight: 1
        $x_1_16 = "DelegateWow64GetThreadContext" ascii //weight: 1
        $x_1_17 = "DelegateGetThreadContext" ascii //weight: 1
        $x_1_18 = "DelegateVirtualAllocEx" ascii //weight: 1
        $x_1_19 = "DelegateWriteProcessMemory" ascii //weight: 1
        $x_1_20 = "DelegateReadProcessMemory" ascii //weight: 1
        $x_1_21 = "DelegateZwUnmapViewOfSection" ascii //weight: 1
        $x_1_22 = "DelegateCreateProcessA" ascii //weight: 1
        $x_1_23 = "GetDelegateForFunctionPointer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_2147772754_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}" wide //weight: 1
        $x_1_2 = "kernel32" wide //weight: 1
        $x_1_3 = "Wow64GetThreadContext" wide //weight: 1
        $x_1_4 = "GetThreadContext" wide //weight: 1
        $x_1_5 = "VirtualAllocEx" wide //weight: 1
        $x_1_6 = "WriteProcessMemory" wide //weight: 1
        $x_1_7 = "ReadProcessMemory" wide //weight: 1
        $x_1_8 = "ntdll" wide //weight: 1
        $x_1_9 = "ZwUnmapViewOfSection" wide //weight: 1
        $x_1_10 = "CreateProcessA" wide //weight: 1
        $x_1_11 = "ResumeThread" wide //weight: 1
        $x_1_12 = "Wow64SetThreadContext" wide //weight: 1
        $x_1_13 = "SetThreadContext" wide //weight: 1
        $x_1_14 = "trump2020" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_2147772754_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "GetProcessById" ascii //weight: 1
        $x_1_3 = "ResumeThread" ascii //weight: 1
        $x_1_4 = "add_Load" ascii //weight: 1
        $x_1_5 = "add_LinkClicked" ascii //weight: 1
        $x_1_6 = "set_LinkVisited" ascii //weight: 1
        $x_1_7 = "DownloadFile" ascii //weight: 1
        $x_1_8 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_9 = "GetTempFileName" ascii //weight: 1
        $x_1_10 = "System.Threading" ascii //weight: 1
        $x_1_11 = "System.Drawing" ascii //weight: 1
        $x_1_12 = "System.Security.Principal" ascii //weight: 1
        $x_1_13 = "Kill" ascii //weight: 1
        $x_1_14 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_15 = "ProcessStartInfo" ascii //weight: 1
        $x_1_16 = "ReadAllBytes" ascii //weight: 1
        $x_1_17 = "WriteAllBytes" ascii //weight: 1
        $x_1_18 = "CreateProcess" ascii //weight: 1
        $x_1_19 = "WebClient" ascii //weight: 1
        $x_1_20 = "get_EntryPoint" ascii //weight: 1
        $x_1_21 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_22 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_23 = "VirtualAllocEx" ascii //weight: 1
        $x_1_24 = "Mutex" ascii //weight: 1
        $x_1_25 = "RegistryKey" ascii //weight: 1
        $x_1_26 = "ExecuteNonQuery" ascii //weight: 1
        $x_1_27 = "ReadProcessMemory" ascii //weight: 1
        $x_1_28 = "WriteProcessMemory" ascii //weight: 1
        $x_1_29 = "GetRuntimeDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_2147772754_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<PrivateImplementationDetails>{" ascii //weight: 1
        $x_1_2 = "get_Size" ascii //weight: 1
        $x_1_3 = "get_Width" ascii //weight: 1
        $x_1_4 = "get_Height" ascii //weight: 1
        $x_1_5 = "get_R" ascii //weight: 1
        $x_1_6 = "get_G" ascii //weight: 1
        $x_1_7 = "get_B" ascii //weight: 1
        $x_1_8 = "get_UserName" ascii //weight: 1
        $x_1_9 = "get_EntryPoint" ascii //weight: 1
        $x_1_10 = "get_CurrentDomain" ascii //weight: 1
        $x_1_11 = "get_X" ascii //weight: 1
        $x_1_12 = "get_Y" ascii //weight: 1
        $x_1_13 = "get_Black" ascii //weight: 1
        $x_1_14 = "get_White" ascii //weight: 1
        $x_1_15 = "get_Red" ascii //weight: 1
        $x_1_16 = "ThreadStart" ascii //weight: 1
        $x_1_17 = "GetProcesses" ascii //weight: 1
        $x_1_18 = "System.Security.AccessControl" ascii //weight: 1
        $x_1_19 = "WebClient" ascii //weight: 1
        $x_1_20 = "DownloadFile" ascii //weight: 1
        $x_1_21 = "GetTempPath" ascii //weight: 1
        $x_1_22 = "LoadXml" ascii //weight: 1
        $x_1_23 = "System.Runtime.Remoting" ascii //weight: 1
        $x_1_24 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_25 = "FromBase64String" ascii //weight: 1
        $x_1_26 = "CreateDecryptor" ascii //weight: 1
        $x_1_27 = "set_Key" ascii //weight: 1
        $x_1_28 = "set_IV" ascii //weight: 1
        $x_1_29 = "CreateEncryptor" ascii //weight: 1
        $x_1_30 = "ToBase64String" ascii //weight: 1
        $x_1_31 = "{11111-22222-10009-11112}" wide //weight: 1
        $x_1_32 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_33 = "GetDelegateForFunctionPointer" wide //weight: 1
        $x_1_34 = "file:///" wide //weight: 1
        $x_1_35 = "Location" wide //weight: 1
        $x_1_36 = "{11111-22222-20001-00001}" wide //weight: 1
        $x_1_37 = "{11111-22222-20001-00002}" wide //weight: 1
        $x_1_38 = "{11111-22222-30001-00001}" wide //weight: 1
        $x_1_39 = "{11111-22222-30001-00002}" wide //weight: 1
        $x_1_40 = "{11111-22222-40001-00001}" wide //weight: 1
        $x_1_41 = "{11111-22222-40001-00002}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_2147772754_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "725"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<PrivateImplementationDetails>" ascii //weight: 1
        $x_1_2 = "ManagementObjectSearcher" ascii //weight: 1
        $x_1_3 = "System.Drawing" ascii //weight: 1
        $x_1_4 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_5 = "set_UseVisualStyleBackColor" ascii //weight: 1
        $x_1_6 = "System.Threading" ascii //weight: 1
        $x_1_7 = "get_Key" ascii //weight: 1
        $x_1_8 = "System.Security.AccessControl" ascii //weight: 1
        $x_1_9 = "SetAccessRuleProtection" ascii //weight: 1
        $x_1_10 = "FileSystemAccessRule" ascii //weight: 1
        $x_1_11 = "get_UserName" ascii //weight: 1
        $x_1_12 = "set_WindowStyle" ascii //weight: 1
        $x_1_13 = "System.Net" ascii //weight: 1
        $x_1_14 = "DownloadFile" ascii //weight: 1
        $x_1_15 = "Kill" ascii //weight: 1
        $x_1_16 = "get_EntryPoint" ascii //weight: 1
        $x_1_17 = "Bitmap" ascii //weight: 1
        $x_1_18 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_19 = "System.Runtime.Remoting" ascii //weight: 1
        $x_1_20 = "FromBase64String" ascii //weight: 1
        $x_1_21 = "set_Key" ascii //weight: 1
        $x_1_22 = "set_IV" ascii //weight: 1
        $x_1_23 = "CreateDecryptor" ascii //weight: 1
        $x_1_24 = "CreateEncryptor" ascii //weight: 1
        $x_1_25 = "ToBase64String" ascii //weight: 1
        $x_50_26 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 50
        $x_50_27 = "{11111-22222-10009-11112}" wide //weight: 50
        $x_50_28 = "{11111-22222-50001-00000}" wide //weight: 50
        $x_50_29 = "GetDelegateForFunctionPointer" wide //weight: 50
        $x_50_30 = "file:///" wide //weight: 50
        $x_50_31 = "Location" wide //weight: 50
        $x_50_32 = "{11111-22222-20001-00001}" wide //weight: 50
        $x_50_33 = "{11111-22222-20001-00002}" wide //weight: 50
        $x_50_34 = "{11111-22222-30001-00001}" wide //weight: 50
        $x_50_35 = "{11111-22222-30001-00002}" wide //weight: 50
        $x_50_36 = "{11111-22222-40001-00001}" wide //weight: 50
        $x_50_37 = "{11111-22222-40001-00002}" wide //weight: 50
        $x_50_38 = "{11111-22222-50001-00001}" wide //weight: 50
        $x_50_39 = "{11111-22222-50001-00002}" wide //weight: 50
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_2147772754_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "682"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "<PrivateImplementationDetails>{" ascii //weight: 1
        $x_1_3 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_4 = "set_UseVisualStyleBackColor" ascii //weight: 1
        $x_1_5 = "set_AutoScaleDimensions" ascii //weight: 1
        $x_1_6 = "System.Threading" ascii //weight: 1
        $x_1_7 = "System.Security.AccessControl" ascii //weight: 1
        $x_1_8 = "SetAccessRuleProtection" ascii //weight: 1
        $x_1_9 = "ProcessStartInfo" ascii //weight: 1
        $x_1_10 = "System.Net" ascii //weight: 1
        $x_1_11 = "get_EntryPoint" ascii //weight: 1
        $x_1_12 = "get_UserName" ascii //weight: 1
        $x_1_13 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_14 = "DownloadFile" ascii //weight: 1
        $x_1_15 = "GetProcessById" ascii //weight: 1
        $x_1_16 = "Kill" ascii //weight: 1
        $x_1_17 = "GetRuntimeDirectory" ascii //weight: 1
        $x_1_18 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_19 = "System.Runtime.Remoting" ascii //weight: 1
        $x_1_20 = "FromBase64String" ascii //weight: 1
        $x_1_21 = "set_Key" ascii //weight: 1
        $x_1_22 = "set_IV" ascii //weight: 1
        $x_1_23 = "CreateDecryptor" ascii //weight: 1
        $x_1_24 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_25 = "ToBase64String" ascii //weight: 1
        $x_1_26 = "CreateEncryptor" ascii //weight: 1
        $x_1_27 = "FlushFinalBlock" ascii //weight: 1
        $x_1_28 = "FileStream" ascii //weight: 1
        $x_1_29 = "FileMode" ascii //weight: 1
        $x_1_30 = "FileAccess" ascii //weight: 1
        $x_1_31 = "FileShare" ascii //weight: 1
        $x_1_32 = "get_AllowOnlyFipsAlgorithms" ascii //weight: 1
        $x_50_33 = "{11111-22222-10009-11112}" wide //weight: 50
        $x_50_34 = "{11111-22222-50001-00000}" wide //weight: 50
        $x_50_35 = "GetDelegateForFunctionPointer" wide //weight: 50
        $x_50_36 = "file:///" wide //weight: 50
        $x_50_37 = "Location" wide //weight: 50
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

rule Trojan_MSIL_StealerLoader_2147772754_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "49"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_TerminalServerSession" ascii //weight: 1
        $x_1_2 = "GetProcessesByName" ascii //weight: 1
        $x_1_3 = "ParameterizedThreadStart" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "GetFileNameWithoutExtension" ascii //weight: 1
        $x_1_6 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_7 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_8 = "GetCurrentProcess" ascii //weight: 1
        $x_1_9 = "WebClient" ascii //weight: 1
        $x_1_10 = "DownloadFile" ascii //weight: 1
        $x_1_11 = "set_UserAgent" ascii //weight: 1
        $x_1_12 = "get_DefaultCredentials" ascii //weight: 1
        $x_1_13 = "get_Is64BitOperatingSystem" ascii //weight: 1
        $x_1_14 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_15 = "RandomNumberGenerator" ascii //weight: 1
        $x_1_16 = "System.Runtime.Remoting" ascii //weight: 1
        $x_1_17 = "FromBase64String" ascii //weight: 1
        $x_1_18 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_19 = "set_Key" ascii //weight: 1
        $x_1_20 = "set_IV" ascii //weight: 1
        $x_1_21 = "CreateDecryptor" ascii //weight: 1
        $x_1_22 = "CreateEncryptor" ascii //weight: 1
        $x_1_23 = "ToBase64String" ascii //weight: 1
        $x_1_24 = "GetOpenClipboardWindow" ascii //weight: 1
        $x_1_25 = "{11111-22222-10009-11112}" wide //weight: 1
        $x_1_26 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_27 = "file:///" wide //weight: 1
        $x_1_28 = "Location" wide //weight: 1
        $x_1_29 = "Find" wide //weight: 1
        $x_1_30 = "ResourceA" wide //weight: 1
        $x_1_31 = "Virtual" wide //weight: 1
        $x_1_32 = "Alloc" wide //weight: 1
        $x_1_33 = "Write" wide //weight: 1
        $x_1_34 = "Memory" wide //weight: 1
        $x_1_35 = "Protect" wide //weight: 1
        $x_1_36 = "Open" wide //weight: 1
        $x_1_37 = "Process" wide //weight: 1
        $x_1_38 = "Close" wide //weight: 1
        $x_1_39 = "Handle" wide //weight: 1
        $x_1_40 = "kernel" wide //weight: 1
        $x_1_41 = "32.dll" wide //weight: 1
        $x_1_42 = "{11111-22222-20001-00001}" wide //weight: 1
        $x_1_43 = "{11111-22222-20001-00002}" wide //weight: 1
        $x_1_44 = "{11111-22222-30001-00001}" wide //weight: 1
        $x_1_45 = "{11111-22222-30001-00002}" wide //weight: 1
        $x_1_46 = "{11111-22222-40001-00001}" wide //weight: 1
        $x_1_47 = "{11111-22222-40001-00002}" wide //weight: 1
        $x_1_48 = "{11111-22222-50001-00001}" wide //weight: 1
        $x_1_49 = "{11111-22222-50001-00002}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_2147772754_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "47"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<PrivateImplementationDetails>{" ascii //weight: 1
        $x_1_2 = "System.IO.Compression" ascii //weight: 1
        $x_1_3 = "RegistryKeyPermissionCheck" ascii //weight: 1
        $x_1_4 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_5 = "GetFileNameWithoutExtension" ascii //weight: 1
        $x_1_6 = "System.Threading" ascii //weight: 1
        $x_1_7 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_10 = "Kill" ascii //weight: 1
        $x_1_11 = "GetRuntimeDirectory" ascii //weight: 1
        $x_1_12 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_13 = "System.Runtime.Remoting" ascii //weight: 1
        $x_1_14 = "get_AllowOnlyFipsAlgorithms" ascii //weight: 1
        $x_1_15 = "System.Reflection.Emit" ascii //weight: 1
        $x_1_16 = "set_Key" ascii //weight: 1
        $x_1_17 = "set_IV" ascii //weight: 1
        $x_1_18 = "CreateDecryptor" ascii //weight: 1
        $x_1_19 = "ToBase64String" ascii //weight: 1
        $x_1_20 = "CreateEncryptor" ascii //weight: 1
        $x_1_21 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 1
        $x_1_22 = "{11111-22222-10009-11112}" wide //weight: 1
        $x_1_23 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_24 = "GetDelegateForFunctionPointer" wide //weight: 1
        $x_1_25 = "file:///" wide //weight: 1
        $x_1_26 = "Location" wide //weight: 1
        $x_1_27 = "Find" wide //weight: 1
        $x_1_28 = "ResourceA" wide //weight: 1
        $x_1_29 = "Virtual" wide //weight: 1
        $x_1_30 = "Alloc" wide //weight: 1
        $x_1_31 = "Write" wide //weight: 1
        $x_1_32 = "Memory" wide //weight: 1
        $x_1_33 = "Protect" wide //weight: 1
        $x_1_34 = "Open" wide //weight: 1
        $x_1_35 = "Process" wide //weight: 1
        $x_1_36 = "Close" wide //weight: 1
        $x_1_37 = "Handle" wide //weight: 1
        $x_1_38 = "kernel" wide //weight: 1
        $x_1_39 = "32.dll" wide //weight: 1
        $x_1_40 = "{11111-22222-20001-00001}" wide //weight: 1
        $x_1_41 = "{11111-22222-20001-00002}" wide //weight: 1
        $x_1_42 = "{11111-22222-30001-00001}" wide //weight: 1
        $x_1_43 = "{11111-22222-30001-00002}" wide //weight: 1
        $x_1_44 = "{11111-22222-40001-00001}" wide //weight: 1
        $x_1_45 = "{11111-22222-40001-00002}" wide //weight: 1
        $x_1_46 = "{11111-22222-50001-00001}" wide //weight: 1
        $x_1_47 = "{11111-22222-50001-00002}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_2147772754_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader!MTB"
        threat_id = "2147772754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "67"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegistryKeyPermissionCheck" ascii //weight: 1
        $x_1_2 = "GetFileNameWithoutExtension" ascii //weight: 1
        $x_1_3 = "GetProcessesByName" ascii //weight: 1
        $x_1_4 = "get_ExecutablePath" ascii //weight: 1
        $x_1_5 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_6 = "System.Reflection.Emit" ascii //weight: 1
        $x_1_7 = "System.Runtime.Remoting" ascii //weight: 1
        $x_1_8 = "get_AllowOnlyFipsAlgorithms" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
        $x_1_10 = "set_IV" ascii //weight: 1
        $x_1_11 = "$$method0x600" ascii //weight: 1
        $x_1_12 = "ProcessStartInfo" ascii //weight: 1
        $x_1_13 = "System.Threading" ascii //weight: 1
        $x_1_14 = "System.Text.RegularExpressions" ascii //weight: 1
        $x_1_15 = "get_Height" ascii //weight: 1
        $x_1_16 = "get_Width" ascii //weight: 1
        $x_1_17 = "get_Is64BitOperatingSystem" ascii //weight: 1
        $x_1_18 = "get_Now" ascii //weight: 1
        $x_1_19 = "get_TotalMilliseconds" ascii //weight: 1
        $x_1_20 = "WindowsBuiltInRole" ascii //weight: 1
        $x_1_21 = "DriveInfo" ascii //weight: 1
        $x_1_22 = "WriteAllText" ascii //weight: 1
        $x_1_23 = "set_FileName" ascii //weight: 1
        $x_1_24 = "WriteAllBytes" ascii //weight: 1
        $x_1_25 = "set_UseShellExecute" ascii //weight: 1
        $x_1_26 = "Kill" ascii //weight: 1
        $x_1_27 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_28 = "get_UserName" ascii //weight: 1
        $x_1_29 = "GetWindowThreadProcessId" ascii //weight: 1
        $x_1_30 = "EnumChildWindows" ascii //weight: 1
        $x_1_31 = "EnumProcesses" ascii //weight: 1
        $x_1_32 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_33 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_34 = "get_X" ascii //weight: 1
        $x_1_35 = "set_Width" ascii //weight: 1
        $x_1_36 = "get_Y" ascii //weight: 1
        $x_1_37 = "set_Height" ascii //weight: 1
        $x_1_38 = "get_CurrentDomain" ascii //weight: 1
        $x_1_39 = "LoadFile" ascii //weight: 1
        $x_1_40 = "FromBase64String" ascii //weight: 1
        $x_1_41 = "ToBase64String" ascii //weight: 1
        $x_1_42 = "{0}{1}\\" wide //weight: 1
        $x_1_43 = ".dll" wide //weight: 1
        $x_1_44 = "w3wp.exe" wide //weight: 1
        $x_1_45 = "aspnet_wp.exe" wide //weight: 1
        $x_1_46 = "{11111-22222-10009-11111}" wide //weight: 1
        $x_1_47 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_48 = "System.Reflection.ReflectionContext" wide //weight: 1
        $x_1_49 = "Location" wide //weight: 1
        $x_1_50 = "Find" wide //weight: 1
        $x_1_51 = "ResourceA" wide //weight: 1
        $x_1_52 = "Virtual" wide //weight: 1
        $x_1_53 = "Alloc" wide //weight: 1
        $x_1_54 = "Write" wide //weight: 1
        $x_1_55 = "Process" wide //weight: 1
        $x_1_56 = "Memory" wide //weight: 1
        $x_1_57 = "Protect" wide //weight: 1
        $x_1_58 = "Close" wide //weight: 1
        $x_1_59 = "Handle" wide //weight: 1
        $x_1_60 = "kernel" wide //weight: 1
        $x_1_61 = "32.dll" wide //weight: 1
        $x_1_62 = "{11111-22222-10001-00001}" wide //weight: 1
        $x_1_63 = "{11111-22222-10001-00002}" wide //weight: 1
        $x_1_64 = "{11111-22222-40001-00001}" wide //weight: 1
        $x_1_65 = "{11111-22222-40001-00002}" wide //weight: 1
        $x_1_66 = "{11111-22222-50001-00001}" wide //weight: 1
        $x_1_67 = "{11111-22222-50001-00002}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_AD_2147778650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader.AD!MTB"
        threat_id = "2147778650"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mutex" ascii //weight: 1
        $x_1_2 = "System.Threading" ascii //weight: 1
        $x_1_3 = "CreateProcess" ascii //weight: 1
        $x_1_4 = "GetThreadContext" ascii //weight: 1
        $x_1_5 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_6 = "SetThreadContext" ascii //weight: 1
        $x_1_7 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_8 = "ReadProcessMemory" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_11 = "VirtualAllocEx" ascii //weight: 1
        $x_1_12 = "ResumeThread" ascii //weight: 1
        $x_1_13 = "ThreadStart" ascii //weight: 1
        $x_1_14 = "WebClient" ascii //weight: 1
        $x_1_15 = "System.Net" ascii //weight: 1
        $x_1_16 = "get_CurrentDomain" ascii //weight: 1
        $x_1_17 = "add_Load" ascii //weight: 1
        $x_1_18 = "ExecuteNonQuery" ascii //weight: 1
        $x_1_19 = "CreateSubKey" ascii //weight: 1
        $x_1_20 = "SetValue" ascii //weight: 1
        $x_1_21 = "set_FileName" ascii //weight: 1
        $x_1_22 = "set_Arguments" ascii //weight: 1
        $x_1_23 = "set_UseShellExecute" ascii //weight: 1
        $x_1_24 = "set_RedirectStandardOutput" ascii //weight: 1
        $x_1_25 = "set_WindowStyle" ascii //weight: 1
        $x_1_26 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_27 = "set_StartInfo" ascii //weight: 1
        $x_1_28 = "DownloadFile" ascii //weight: 1
        $x_1_29 = "Kill" ascii //weight: 1
        $x_1_30 = "ReadAllBytes" ascii //weight: 1
        $x_1_31 = "WriteAllBytes" ascii //weight: 1
        $x_1_32 = "get_EntryPoint" ascii //weight: 1
        $x_1_33 = "GetRuntimeDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_AD_2147778650_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader.AD!MTB"
        threat_id = "2147778650"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<PrivateImplementationDetails>{" ascii //weight: 1
        $x_1_2 = "System.Security.Principal" ascii //weight: 1
        $x_1_3 = "ProcessStartInfo" ascii //weight: 1
        $x_1_4 = "set_FileName" ascii //weight: 1
        $x_1_5 = "set_Arguments" ascii //weight: 1
        $x_1_6 = "set_WindowStyle" ascii //weight: 1
        $x_1_7 = "set_StartInfo" ascii //weight: 1
        $x_1_8 = "System.Threading" ascii //weight: 1
        $x_1_9 = "FileSystemAccessRule" ascii //weight: 1
        $x_1_10 = "System.Net" ascii //weight: 1
        $x_1_11 = "SetAccessRuleProtection" ascii //weight: 1
        $x_1_12 = "DownloadFile" ascii //weight: 1
        $x_1_13 = "ClearProjectError" ascii //weight: 1
        $x_1_14 = "get_UserName" ascii //weight: 1
        $x_1_15 = "get_EntryPoint" ascii //weight: 1
        $x_1_16 = "currentDirectory" ascii //weight: 1
        $x_1_17 = "CreateDirectory" ascii //weight: 1
        $x_1_18 = "System.Data.SqlClient" ascii //weight: 1
        $x_1_19 = "ExecuteNonQuery" ascii //weight: 1
        $x_1_20 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_21 = "System.Runtime.Remoting" ascii //weight: 1
        $x_1_22 = "FromBase64String" ascii //weight: 1
        $x_1_23 = "set_Key" ascii //weight: 1
        $x_1_24 = "set_IV" ascii //weight: 1
        $x_1_25 = "CreateDecryptor" ascii //weight: 1
        $x_1_26 = "CreateEncryptor" ascii //weight: 1
        $x_1_27 = "ToBase64String" ascii //weight: 1
        $x_1_28 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_29 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 1
        $x_1_30 = "{11111-22222-10009-11112}" wide //weight: 1
        $x_1_31 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_32 = "GetDelegateForFunctionPointer" wide //weight: 1
        $x_1_33 = "file:///" wide //weight: 1
        $x_1_34 = "Location" wide //weight: 1
        $x_1_35 = "{11111-22222-20001-00001}" wide //weight: 1
        $x_1_36 = "{11111-22222-20001-00002}" wide //weight: 1
        $x_1_37 = "{11111-22222-30001-00001}" wide //weight: 1
        $x_1_38 = "{11111-22222-30001-00002}" wide //weight: 1
        $x_1_39 = "{11111-22222-40001-00001}" wide //weight: 1
        $x_1_40 = "{11111-22222-40001-00002}" wide //weight: 1
        $x_1_41 = "{11111-22222-50001-00001}" wide //weight: 1
        $x_1_42 = "{11111-22222-50001-00002}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_AB_2147780079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader.AB!MTB"
        threat_id = "2147780079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DelegateWow64SetThreadContext" ascii //weight: 1
        $x_1_2 = "DelegateSetThreadContext" ascii //weight: 1
        $x_1_3 = "DelegateWow64GetThreadContext" ascii //weight: 1
        $x_1_4 = "DelegateGetThreadContext" ascii //weight: 1
        $x_1_5 = "DelegateVirtualAllocEx" ascii //weight: 1
        $x_1_6 = "DelegateWriteProcessMemory" ascii //weight: 1
        $x_1_7 = "DelegateReadProcessMemory" ascii //weight: 1
        $x_1_8 = "DelegateZwUnmapViewOfSection" ascii //weight: 1
        $x_1_9 = "DelegateCreateProcessA" ascii //weight: 1
        $x_1_10 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_11 = "VirtualProtect" ascii //weight: 1
        $x_1_12 = "System.Threading" ascii //weight: 1
        $x_1_13 = "ParameterizedThreadStart" ascii //weight: 1
        $x_1_14 = "NtQueryInformationProcess" ascii //weight: 1
        $x_1_15 = "XOR_DEC" ascii //weight: 1
        $x_1_16 = "ProcessPersistenceWatcher" ascii //weight: 1
        $x_1_17 = "AllowAccess" ascii //weight: 1
        $x_1_18 = "ProtectTheFile" ascii //weight: 1
        $x_1_19 = "Startup" ascii //weight: 1
        $x_1_20 = "LoadApi" ascii //weight: 1
        $x_1_21 = "CreateApi" ascii //weight: 1
        $x_1_22 = "StartInject" ascii //weight: 1
        $x_1_23 = "GetInjectionPath" ascii //weight: 1
        $x_1_24 = "FileSystemAccessRule" ascii //weight: 1
        $x_1_25 = "DownloadFile" ascii //weight: 1
        $x_1_26 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_27 = "Kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_MK_2147789393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader.MK!MTB"
        threat_id = "2147789393"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunPE\\obj\\Debug\\RunPE.pdb" ascii //weight: 1
        $x_1_2 = "get_ASCII" ascii //weight: 1
        $x_1_3 = "GetProcessById" ascii //weight: 1
        $x_1_4 = "get_Assembly" ascii //weight: 1
        $x_1_5 = "get_WebServices" ascii //weight: 1
        $x_1_6 = "get_Modules" ascii //weight: 1
        $x_1_7 = "RunPE.Resources" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "ResumeThread" ascii //weight: 1
        $x_1_10 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_11 = "ReadProcessMemory" ascii //weight: 1
        $x_1_12 = "GetThreadContext" ascii //weight: 1
        $x_1_13 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_14 = "VirtualAllocEx" ascii //weight: 1
        $x_1_15 = "LoadLibraryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerLoader_MAK_2147805388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerLoader.MAK!MTB"
        threat_id = "2147805388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SbieDll.dll" ascii //weight: 1
        $x_1_2 = "SerialNumber" ascii //weight: 1
        $x_1_3 = "vmware" ascii //weight: 1
        $x_1_4 = "dnspy" ascii //weight: 1
        $x_1_5 = "select * from Win32_BIOS" ascii //weight: 1
        $x_1_6 = "Microsoft|VMWare|Virtual" ascii //weight: 1
        $x_1_7 = "manufacturer" ascii //weight: 1
        $x_1_8 = "select * from Win32_ComputerSystem" ascii //weight: 1
        $x_1_9 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 [0-48] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
        $x_1_10 = {70 6f 77 65 72 73 68 65 6c 6c 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 [0-48] 2e 76 62 73}  //weight: 1, accuracy: Low
        $x_1_11 = "CommandLine \"rmdir 'C:\\ProgramData\\Microsoft\\Windows Defender' -Recurse\"" ascii //weight: 1
        $x_1_12 = "CommandLine \"stop WinDefend\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

