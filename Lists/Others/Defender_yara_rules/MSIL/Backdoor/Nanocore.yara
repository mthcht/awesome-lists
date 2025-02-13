rule Backdoor_MSIL_Nanocore_2147740145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore!MTB"
        threat_id = "2147740145"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReZer0.Properties" ascii //weight: 1
        $x_1_2 = "ReZer0V2" ascii //weight: 1
        $x_1_3 = "System.CodeDom.Compiler" ascii //weight: 1
        $x_1_4 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_5 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_2147740145_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore!MTB"
        threat_id = "2147740145"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateSubKey" ascii //weight: 1
        $x_1_2 = "SetValue" ascii //weight: 1
        $x_1_3 = "set_FileName" ascii //weight: 1
        $x_1_4 = "set_Arguments" ascii //weight: 1
        $x_1_5 = "set_UseShellExecute" ascii //weight: 1
        $x_1_6 = "set_RedirectStandardOutput" ascii //weight: 1
        $x_1_7 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_8 = "set_StartInfo" ascii //weight: 1
        $x_1_9 = "get_StandardOutput" ascii //weight: 1
        $x_1_10 = "ReZer0V2.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_2147740145_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore!MTB"
        threat_id = "2147740145"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_2 = "set_UseShellExecute" ascii //weight: 1
        $x_1_3 = "PROCESS_CREATE_PROCESS" ascii //weight: 1
        $x_1_4 = "PROCESS_DUP_HANDLE" ascii //weight: 1
        $x_1_5 = "PROCESS_VM_OPERATION" ascii //weight: 1
        $x_1_6 = "PROCESS_VM_READ" ascii //weight: 1
        $x_1_7 = "PROCESS_VM_WRITE" ascii //weight: 1
        $x_1_8 = "PROCESS_ALL_ACCESS" ascii //weight: 1
        $x_1_9 = "SUSPEND_RESUME" ascii //weight: 1
        $x_1_10 = "DIRECT_IMPERSONATION" ascii //weight: 1
        $x_1_11 = "SYNCHRONIZE" ascii //weight: 1
        $x_1_12 = "STANDARD_RIGHTS_REQUIRED" ascii //weight: 1
        $x_1_13 = "THREAD_ALL_ACCESS" ascii //weight: 1
        $x_7_14 = ".crypted.exe" wide //weight: 7
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_7_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Nanocore_2147740145_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore!MTB"
        threat_id = "2147740145"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 00 59 7e ?? ?? ?? 04 61 d1 2a 40 00 20 ?? ?? ?? 00 13 ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 40 ?? ?? ?? ?? 20 ?? ?? ?? ?? 13 ?? 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_2147740145_4
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore!MTB"
        threat_id = "2147740145"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 82 00 00 0a 00 16 28 83 00 00 0a 00 28 84 00 00 0a 28 08 00 00 06 6f 85 00 00 0a 0a 06 72 ?? 07 00 70 6f 86 00 00 0a 0b 07 72 ?? 08 00 70 6f 87 00 00 0a 0c 07 28 88 00 00 0a 0d 73 32 00 00 06 13 04 1f 09 8d 38 00 00 01 25}  //weight: 1, accuracy: Low
        $x_1_2 = {28 89 00 00 0a 13 05 08 14 72 ?? 08 00 70 18 8d 14 00 00 01 25 16 09 a2 25 17 17 8d 14 00 00 01 25 16 11 05 a2 a2 14 14 28 8a 00 00 0a 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_2147740145_5
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore!MTB"
        threat_id = "2147740145"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PROCESS_INFORMATION" ascii //weight: 1
        $x_1_2 = "STARTUP_INFORMATION" ascii //weight: 1
        $x_1_3 = "SetThread" ascii //weight: 1
        $x_1_4 = "FileAccess" ascii //weight: 1
        $x_1_5 = "IWshShell" ascii //weight: 1
        $x_1_6 = "Convert" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_9 = "set_UseShellExecute" ascii //weight: 1
        $x_3_10 = "CheckRemoteDebuggerPresent" ascii //weight: 3
        $x_3_11 = "VirtualMachineDetector" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Nanocore_2147740145_6
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore!MTB"
        threat_id = "2147740145"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_2 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_3 = "IClientNetwork" ascii //weight: 1
        $x_1_4 = "LockResource" ascii //weight: 1
        $x_1_5 = "GetKernelObjectSecurity" ascii //weight: 1
        $x_1_6 = "NanoCore Client.exe" ascii //weight: 1
        $x_1_7 = "Enqueue" ascii //weight: 1
        $x_1_8 = "ClientLoaderForm.resources" ascii //weight: 1
        $x_1_9 = "ClientUninstalling" ascii //weight: 1
        $x_1_10 = "LogClientMessage" ascii //weight: 1
        $x_1_11 = "NanoCore.ClientPlugin" ascii //weight: 1
        $x_1_12 = "DisableProtection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_S_2147752157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore.S!MTB"
        threat_id = "2147752157"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NanoCore.ClientPlugin" ascii //weight: 1
        $x_1_2 = "NanoCore.ClientPluginHost" ascii //weight: 1
        $x_1_3 = "ConnectionStateChanged" ascii //weight: 1
        $x_1_4 = "get_StartupPath" ascii //weight: 1
        $x_1_5 = "set_UseShellExecute" ascii //weight: 1
        $x_1_6 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_7 = "FileAccess" ascii //weight: 1
        $x_1_8 = "ReadBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_GG_2147772077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore.GG!MTB"
        threat_id = "2147772077"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NanoCore.ClientPlugin" ascii //weight: 1
        $x_1_2 = "MyClientPlugin.dll" ascii //weight: 1
        $x_1_3 = "\\Downloads\\NanoCoreSwiss\\MyClientPlugin\\obj\\Debug\\MyClientPlugin.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_ABD_2147827400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore.ABD!MTB"
        threat_id = "2147827400"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b bf 00 02 28 e9 ?? ?? 06 03 6f dd ?? ?? 06 02 28 eb ?? ?? 06 03 6f dd ?? ?? 06 02 28 ed ?? ?? 06 03 6f dd ?? ?? 06 02 fe 06 ?? ?? ?? 06 73 53 ?? ?? 0a 02 fe 06 ?? ?? ?? 06 73 54 ?? ?? 0a 28 42 ?? ?? 06 0a 20 74 ?? ?? 59 38 72 ?? ?? ff 2b 99 20 5c ?? ?? 6e 38 66 ?? ?? ff 2b f2 6a 00 07 20 70 ?? ?? 02 5a 20 92 ?? ?? 98 61}  //weight: 3, accuracy: Low
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "GetEnumerator" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
        $x_1_7 = "ResolveMethod" ascii //weight: 1
        $x_1_8 = "CreateDelegate" ascii //weight: 1
        $x_1_9 = "ReadBytes" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_ABD_2147827400_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore.ABD!MTB"
        threat_id = "2147827400"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7f bf b6 3f 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 9e 01 00 00 fa 00 00 00 ac 03 00 00 ac 03 00 00 39 05 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "GetLogger" ascii //weight: 1
        $x_1_3 = "get_IsDebugOn" ascii //weight: 1
        $x_1_4 = "GetRuntimeDirectory" ascii //weight: 1
        $x_1_5 = "IsLaunched" ascii //weight: 1
        $x_1_6 = "ExtractResourceToRootPath" ascii //weight: 1
        $x_1_7 = "InvokeMember" ascii //weight: 1
        $x_1_8 = "get_KeyboardDevice" ascii //weight: 1
        $x_1_9 = "Turn on your av" wide //weight: 1
        $x_1_10 = "Cloaker Get Ty Cloaker pe" wide //weight: 1
        $x_1_11 = "Cloaker Lo a Cloaker d" wide //weight: 1
        $x_1_12 = "Cloaker Inv o Cloaker ke" wide //weight: 1
        $x_1_13 = "/C rmdir /s /q " wide //weight: 1
        $x_1_14 = "Temporary file {0} successfully deleted." wide //weight: 1
        $x_1_15 = "Converting {0} to {1}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_ABQ_2147827744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore.ABQ!MTB"
        threat_id = "2147827744"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 03 02 03 6f 4f ?? ?? 0a 5d 6f 50 ?? ?? 0a 7e 4c ?? ?? 04 02 91 61 d2 0a 2b 00 06 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "ToString" ascii //weight: 1
        $x_1_3 = "DateTimeKind" ascii //weight: 1
        $x_1_4 = "Delegate" ascii //weight: 1
        $x_1_5 = "Encoding" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_ABQ_2147827744_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore.ABQ!MTB"
        threat_id = "2147827744"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 72 00 00 05 65 00 73 00 00 05 6f 00 75 00 00 05 72 00 63 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "GetManifestResourceNames" ascii //weight: 1
        $x_1_3 = "njcvniodsjie98" ascii //weight: 1
        $x_1_4 = "klnvaw" ascii //weight: 1
        $x_1_5 = "22S2y2222s222t22e222m2" ascii //weight: 1
        $x_1_6 = "22R2e2f222l2e2222c22t22i2o2n2" ascii //weight: 1
        $x_1_7 = "A222s2s2e2m222b2l2y2" ascii //weight: 1
        $x_1_8 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_ABK_2147830992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore.ABK!MTB"
        threat_id = "2147830992"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateInstance" ascii //weight: 1
        $x_1_2 = "GetCurrentDirectory" ascii //weight: 1
        $x_1_3 = "b6ca9a8445.res" ascii //weight: 1
        $x_1_4 = "17fac4fc2e19.Resources.resources" ascii //weight: 1
        $x_1_5 = "$6fe07353-243a-415b-9cca-228089c271be" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_ABG_2147831797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore.ABG!MTB"
        threat_id = "2147831797"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 1f 6a 91 13 05 2b 9b 02 73 ?? ?? ?? 0a 0b 07 75 ?? ?? ?? 01 06 75 ?? ?? ?? 01 16 73 ?? ?? ?? 0a 20 ?? ?? ?? 00 8d ?? ?? ?? 01 0c 73 ?? ?? ?? 0a 0d 08 75 ?? ?? ?? 1b 09 75 ?? ?? ?? 01 07 75 ?? ?? ?? 01 28 ?? ?? ?? 06 17 13 05 38 ?? ?? ?? ff 09 75 ?? ?? ?? 01 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 20 ?? ?? ?? 00 7e ?? ?? ?? 04 20 ?? ?? ?? 00 91 7e ?? ?? ?? 04 1f 31 91 5f 20 ?? ?? ?? 00 5f 9c 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "cvhngfg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_ABG_2147831797_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore.ABG!MTB"
        threat_id = "2147831797"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 25 16 72 ?? ?? ?? 70 a2 25 17 72 ?? ?? ?? 70 a2 14 14 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0b 07 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0c 28 ?? ?? ?? 0a 14 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 17 8d ?? ?? ?? 01 25 16 08 a2 14 14 66 00 7e ?? ?? ?? 04 14 72 ?? ?? ?? 70 18 8d 17}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Actions2EventsMapping.Resources" wide //weight: 1
        $x_1_4 = "download" wide //weight: 1
        $x_1_5 = "red_love" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_ABAG_2147833109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore.ABAG!MTB"
        threat_id = "2147833109"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_2 = "IsLogging" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "$609716a2-ded9-47f8-bdec-6849a78a8917" ascii //weight: 1
        $x_1_5 = "PizzaBit.Resources" wide //weight: 1
        $x_1_6 = "download" wide //weight: 1
        $x_1_7 = "red_love" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Nanocore_ABBO_2147834313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocore.ABBO!MTB"
        threat_id = "2147834313"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 6f 7b 00 00 0a 28 a0 00 00 06 28 a7 00 00 06 28 d1 00 00 06 17 9a 80 39 00 00 04 11 07 20 52 7d c7 ae 5a 20 5f 7b 2d b9 61 38 db fd ff ff}  //weight: 2, accuracy: High
        $x_1_2 = "Hyves" ascii //weight: 1
        $x_1_3 = "CheatMenu.Properties.Resources.resources" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

