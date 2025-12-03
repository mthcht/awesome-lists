rule VirTool_MSIL_Lore_AD_2147742672_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore.AD!MTB"
        threat_id = "2147742672"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetEnvironmentVariable" wide //weight: 1
        $x_1_2 = "_ENABLE_PROFILING" wide //weight: 1
        $x_1_3 = "Deserialize.Resources" wide //weight: 1
        $x_1_4 = "RunPe4" wide //weight: 1
        $x_1_5 = "VMDetector" wide //weight: 1
        $x_1_6 = "AppLaunch.exe" wide //weight: 1
        $x_1_7 = "svchost.exe" wide //weight: 1
        $x_1_8 = "RegAsm.exe" wide //weight: 1
        $x_1_9 = "InstallUtil.exe" wide //weight: 1
        $x_1_10 = "%StartupFolder%" wide //weight: 1
        $x_1_11 = "%HiddenReg%" wide //weight: 1
        $x_1_12 = "%HiddenKey%" wide //weight: 1
        $x_1_13 = "%VM%" wide //weight: 1
        $x_1_14 = "%SB%" wide //weight: 1
        $x_1_15 = "%Delay%" wide //weight: 1
        $x_1_16 = "%InjectionPersist%" wide //weight: 1
        $x_1_17 = "%StartupPersist%" wide //weight: 1
        $x_1_18 = "%HostIndex%" wide //weight: 1
        $x_1_19 = "%MainFile%" wide //weight: 1
        $x_1_20 = "%FilesNum%" wide //weight: 1
        $x_1_21 = "%Melt%" wide //weight: 1
        $x_1_22 = "%MeltName%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_AD_2147742672_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore.AD!MTB"
        threat_id = "2147742672"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "722"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<PrivateImplementationDetails>" ascii //weight: 1
        $x_1_2 = "System.IO.Compression" ascii //weight: 1
        $x_1_3 = "System.Drawing" ascii //weight: 1
        $x_1_4 = "get_R" ascii //weight: 1
        $x_1_5 = "get_G" ascii //weight: 1
        $x_1_6 = "get_B" ascii //weight: 1
        $x_1_7 = "get_Length" ascii //weight: 1
        $x_1_8 = "get_Width" ascii //weight: 1
        $x_1_9 = "get_Height" ascii //weight: 1
        $x_1_10 = "GetPixel" ascii //weight: 1
        $x_1_11 = "resource_name" ascii //weight: 1
        $x_1_12 = "project_name" ascii //weight: 1
        $x_1_13 = "System.Threading" ascii //weight: 1
        $x_1_14 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_15 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_16 = "System.Runtime.Remoting" ascii //weight: 1
        $x_1_17 = "FromBase64String" ascii //weight: 1
        $x_1_18 = "ToBase64String" ascii //weight: 1
        $x_1_19 = "set_Key" ascii //weight: 1
        $x_1_20 = "set_IV" ascii //weight: 1
        $x_1_21 = "CreateDecryptor" ascii //weight: 1
        $x_1_22 = "CreateEncryptor" ascii //weight: 1
        $x_50_23 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 50
        $x_50_24 = "{11111-22222-10009-11112}" wide //weight: 50
        $x_50_25 = "{11111-22222-50001-00000}" wide //weight: 50
        $x_50_26 = "GetDelegateForFunctionPointer" wide //weight: 50
        $x_50_27 = "file:///" wide //weight: 50
        $x_50_28 = "Location" wide //weight: 50
        $x_50_29 = "{11111-22222-20001-00001}" wide //weight: 50
        $x_50_30 = "{11111-22222-20001-00002}" wide //weight: 50
        $x_50_31 = "{11111-22222-30001-00001}" wide //weight: 50
        $x_50_32 = "{11111-22222-30001-00002}" wide //weight: 50
        $x_50_33 = "{11111-22222-40001-00001}" wide //weight: 50
        $x_50_34 = "{11111-22222-40001-00002}" wide //weight: 50
        $x_50_35 = "{11111-22222-50001-00001}" wide //weight: 50
        $x_50_36 = "{11111-22222-50001-00002}" wide //weight: 50
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SnakeLib.dll" ascii //weight: 1
        $x_1_2 = "Snake.SIGDU.resources" ascii //weight: 1
        $x_1_3 = "AppDomain" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "asdadad" ascii //weight: 1
        $x_1_2 = "Write" ascii //weight: 1
        $x_1_3 = "ReadByte" ascii //weight: 1
        $x_1_4 = "DebuggingModes" ascii //weight: 1
        $x_1_5 = "BlockCopy" ascii //weight: 1
        $x_1_6 = "$c4099e4c-59be-485d-b0bf-34dea2ad6b4b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_B" ascii //weight: 1
        $x_1_2 = "get_G" ascii //weight: 1
        $x_1_3 = "get_R" ascii //weight: 1
        $x_1_4 = "CoreDB" wide //weight: 1
        $x_1_5 = "RazerSynapse.dll" ascii //weight: 1
        $x_1_6 = "tempuri.org/CoreDB.xsd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MARCUS.dll" ascii //weight: 1
        $x_1_2 = "<Module>" ascii //weight: 1
        $x_1_3 = "System.IO.Compression" ascii //weight: 1
        $x_1_4 = "Bitmap" ascii //weight: 1
        $x_1_5 = "resource_name" ascii //weight: 1
        $x_1_6 = "project_name" ascii //weight: 1
        $x_1_7 = "AppDomain" ascii //weight: 1
        $x_1_8 = "System.Security.Policy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Unhook.dll" ascii //weight: 1
        $x_1_2 = "SmartAssembly.HouseOfCards" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "QAFAST" ascii //weight: 1
        $x_1_7 = "Unhook.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_5
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_2 = "set_KeySize" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "DebuggingModes" ascii //weight: 1
        $x_1_7 = "ZImBOZX.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_6
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "var1" ascii //weight: 1
        $x_1_2 = "var2" ascii //weight: 1
        $x_1_3 = "var3" ascii //weight: 1
        $x_1_4 = "ugz1" ascii //weight: 1
        $x_1_5 = "ugz3" ascii //weight: 1
        $x_1_6 = "projname" ascii //weight: 1
        $x_1_7 = "Guru" ascii //weight: 1
        $x_1_8 = "get_X" ascii //weight: 1
        $x_1_9 = "get_Y" ascii //weight: 1
        $x_1_10 = "get_R" ascii //weight: 1
        $x_1_11 = "get_B" ascii //weight: 1
        $x_1_12 = "get_G" ascii //weight: 1
        $x_1_13 = "NewLateBinding" ascii //weight: 1
        $x_1_14 = "LateCall" ascii //weight: 1
        $x_1_15 = "System.Threading" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_7
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XUKelrouphgPxibFKCvvnfwSeRVm.dll" ascii //weight: 1
        $x_1_2 = "<Module>" ascii //weight: 1
        $x_1_3 = "XUKelrouphgPxibFKCvvnfwSeRVm" ascii //weight: 1
        $x_1_4 = "Deserialize.Resources.resources" ascii //weight: 1
        $x_1_5 = "Deserialize.RunPe4.dec" ascii //weight: 1
        $x_1_6 = "Deserialize.VMDetector.dec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_8
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MARCUS.dll" ascii //weight: 1
        $x_1_2 = "<Module>" ascii //weight: 1
        $x_1_3 = "Jarico" ascii //weight: 1
        $x_1_4 = "System.IO.Compression" ascii //weight: 1
        $x_1_5 = "res_name" ascii //weight: 1
        $x_1_6 = "proj_name" ascii //weight: 1
        $x_1_7 = "Buta" ascii //weight: 1
        $x_1_8 = "resource_name" ascii //weight: 1
        $x_1_9 = "project_name" ascii //weight: 1
        $x_1_10 = "get_R" ascii //weight: 1
        $x_1_11 = "get_G" ascii //weight: 1
        $x_1_12 = "get_B" ascii //weight: 1
        $x_1_13 = "get_Width" ascii //weight: 1
        $x_1_14 = "get_Height" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_9
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D3LLCODE" ascii //weight: 1
        $x_1_2 = "ExecsTARTuP" ascii //weight: 1
        $x_1_3 = "UDecryptU" ascii //weight: 1
        $x_1_4 = "get_IV" ascii //weight: 1
        $x_1_5 = "set_IV" ascii //weight: 1
        $x_1_6 = "get_Tesla" ascii //weight: 1
        $x_1_7 = "DownloadFile" ascii //weight: 1
        $x_1_8 = "UpdateIniFile" ascii //weight: 1
        $x_1_9 = "set_UseShellExecute" ascii //weight: 1
        $x_1_10 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_11 = "Ap$p$ex" wide //weight: 1
        $x_1_12 = "In$J$ct0r" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_10
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "var1" ascii //weight: 1
        $x_1_2 = "var2" ascii //weight: 1
        $x_1_3 = "var3" ascii //weight: 1
        $x_1_4 = "ugz1" ascii //weight: 1
        $x_1_5 = "ugz3" ascii //weight: 1
        $x_1_6 = "projname" ascii //weight: 1
        $x_1_7 = "get_Jonas" ascii //weight: 1
        $x_1_8 = "set_Jonas" ascii //weight: 1
        $x_1_9 = {58 65 48 00 68 65 78}  //weight: 1, accuracy: High
        $x_1_10 = "CallByName" ascii //weight: 1
        $x_1_11 = "get_X" ascii //weight: 1
        $x_1_12 = "get_Y" ascii //weight: 1
        $x_1_13 = "set_X" ascii //weight: 1
        $x_1_14 = "set_Y" ascii //weight: 1
        $x_1_15 = "AppDomain" ascii //weight: 1
        $x_1_16 = "get_CurrentDomain" ascii //weight: 1
        $x_1_17 = "System.Threading" ascii //weight: 1
        $x_1_18 = "Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_11
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "InverseQ" ascii //weight: 1
        $x_1_3 = "CryptoStream" ascii //weight: 1
        $x_1_4 = "AppDomain" ascii //weight: 1
        $x_1_5 = "get_CurrentDomain" ascii //weight: 1
        $x_1_6 = "Bitmap" ascii //weight: 1
        $x_1_7 = "InvokeMember" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
        $x_1_10 = "set_Key" ascii //weight: 1
        $x_1_11 = "dead codeT" ascii //weight: 1
        $x_1_12 = "StripAfterObfuscation" ascii //weight: 1
        $x_1_13 = "PhotoDirector_2.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_12
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "var1" ascii //weight: 1
        $x_1_2 = "var2" ascii //weight: 1
        $x_1_3 = "var3" ascii //weight: 1
        $x_1_4 = "<Module>" ascii //weight: 1
        $x_1_5 = "get_FileName" ascii //weight: 1
        $x_1_6 = "projname" ascii //weight: 1
        $x_1_7 = "System.Threading" ascii //weight: 1
        $x_1_8 = "System.Drawing" ascii //weight: 1
        $x_1_9 = "get_Width" ascii //weight: 1
        $x_1_10 = "get_Length" ascii //weight: 1
        $x_1_11 = "GetPixel" ascii //weight: 1
        $x_1_12 = "ComponentResourceManager" ascii //weight: 1
        $x_1_13 = "get_Jonas" ascii //weight: 1
        $x_1_14 = "set_Jonas" ascii //weight: 1
        $x_1_15 = "Load" wide //weight: 1
        $x_1_16 = ".Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_13
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "get_R" ascii //weight: 1
        $x_1_3 = "get_G" ascii //weight: 1
        $x_1_4 = "get_B" ascii //weight: 1
        $x_1_5 = "resource_name" ascii //weight: 1
        $x_1_6 = "project_name" ascii //weight: 1
        $x_1_7 = "System.Threading" ascii //weight: 1
        $x_1_8 = "System.Drawing" ascii //weight: 1
        $x_1_9 = "get_Width" ascii //weight: 1
        $x_1_10 = "get_Length" ascii //weight: 1
        $x_1_11 = "get_Height" ascii //weight: 1
        $x_1_12 = ".Properties.Resources" wide //weight: 1
        $x_1_13 = "EntryPoint" wide //weight: 1
        $x_1_14 = "Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_14
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "System.IO" ascii //weight: 1
        $x_1_3 = "get_IsPublic" ascii //weight: 1
        $x_1_4 = "System.Collections.Generic" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "CompressionMode" ascii //weight: 1
        $x_1_7 = "get_DeclaringType" ascii //weight: 1
        $x_1_8 = "GZipStream" ascii //weight: 1
        $x_1_9 = "get_CurrentDomain" ascii //weight: 1
        $x_1_10 = "System.IO.Compression" ascii //weight: 1
        $x_1_11 = "System.Reflection" ascii //weight: 1
        $x_1_12 = "InvokeMember" ascii //weight: 1
        $x_1_13 = "Lo!ad" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_15
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "<PrivateImplementationDetails>" ascii //weight: 1
        $x_1_3 = "get_R" ascii //weight: 1
        $x_1_4 = "get_G" ascii //weight: 1
        $x_1_5 = "get_B" ascii //weight: 1
        $x_1_6 = "proj_name" ascii //weight: 1
        $x_1_7 = "res_name" ascii //weight: 1
        $x_1_8 = "System.Threading" ascii //weight: 1
        $x_1_9 = "System.Drawing" ascii //weight: 1
        $x_1_10 = "get_Size" ascii //weight: 1
        $x_1_11 = "get_Width" ascii //weight: 1
        $x_1_12 = "get_Length" ascii //weight: 1
        $x_1_13 = "get_Height" ascii //weight: 1
        $x_1_14 = "GetPixel" ascii //weight: 1
        $x_1_15 = "Bitmap" ascii //weight: 1
        $x_1_16 = "Aphrodite" ascii //weight: 1
        $x_1_17 = "Amphitrite" ascii //weight: 1
        $x_1_18 = "Antheia" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_16
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CoreLoad" ascii //weight: 1
        $x_1_2 = "get_CoreProperty" ascii //weight: 1
        $x_1_3 = "set_CoreProperty" ascii //weight: 1
        $x_1_4 = "CoreLoader" ascii //weight: 1
        $x_1_5 = "AppDomain" ascii //weight: 1
        $x_1_6 = "get_CurrentDomain" ascii //weight: 1
        $x_1_7 = "get_EntryPoint" ascii //weight: 1
        $x_1_8 = "MethodBase" ascii //weight: 1
        $x_1_9 = "Invoke" ascii //weight: 1
        $x_1_10 = "get_Size" ascii //weight: 1
        $x_1_11 = "get_Width" ascii //weight: 1
        $x_1_12 = "GetPixel" ascii //weight: 1
        $x_1_13 = "ToArgb" ascii //weight: 1
        $x_1_14 = "BitConverter" ascii //weight: 1
        $x_1_15 = "GetBytes" ascii //weight: 1
        $x_1_16 = "Buffer" ascii //weight: 1
        $x_1_17 = "BlockCopy" ascii //weight: 1
        $x_1_18 = "CoreProperty" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_17
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "var1" ascii //weight: 1
        $x_1_2 = "var2" ascii //weight: 1
        $x_1_3 = "var3" ascii //weight: 1
        $x_1_4 = "<Module>" ascii //weight: 1
        $x_1_5 = "System.Threading" ascii //weight: 1
        $x_1_6 = "System.Drawing" ascii //weight: 1
        $x_1_7 = "get_Width" ascii //weight: 1
        $x_1_8 = "get_Length" ascii //weight: 1
        $x_1_9 = "GetPixel" ascii //weight: 1
        $x_1_10 = "get_ResourceManager" ascii //weight: 1
        $x_1_11 = "BitConverter" ascii //weight: 1
        $x_1_12 = "Activator" ascii //weight: 1
        $x_1_13 = "get_WrappedObject" ascii //weight: 1
        $x_1_14 = "set_WrappedObject" ascii //weight: 1
        $x_1_15 = "GetEntryAssembly" ascii //weight: 1
        $x_1_16 = "Load" wide //weight: 1
        $x_1_17 = ".Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_18
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\notepad.exe" wide //weight: 1
        $x_1_2 = "\\RegAsm.exe" wide //weight: 1
        $x_1_3 = "\\vbc.exe" wide //weight: 1
        $x_1_4 = "\\cvtres.exe" wide //weight: 1
        $x_1_5 = "\\InstallUtil.exe" wide //weight: 1
        $x_1_6 = "\\AppLaunch.exe" wide //weight: 1
        $x_1_7 = "\\svchost.exe" wide //weight: 1
        $x_1_8 = "TASKKILkilll" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "DebuggerBrowsableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_19
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<PrivateImplementationDetails>{" ascii //weight: 1
        $x_1_2 = "get_Value" ascii //weight: 1
        $x_1_3 = "set_Value" ascii //weight: 1
        $x_1_4 = "var1" ascii //weight: 1
        $x_1_5 = "var2" ascii //weight: 1
        $x_1_6 = "var3" ascii //weight: 1
        $x_1_7 = "get_Width" ascii //weight: 1
        $x_1_8 = "get_Size" ascii //weight: 1
        $x_1_9 = "GetPixel" ascii //weight: 1
        $x_1_10 = "projectname" ascii //weight: 1
        $x_1_11 = "set_ServerPageTimeLimit" ascii //weight: 1
        $x_1_12 = "get_WrappedObject" ascii //weight: 1
        $x_1_13 = "set_WrappedObject" ascii //weight: 1
        $x_1_14 = "System.Threading" ascii //weight: 1
        $x_1_15 = "CreateDelegate" ascii //weight: 1
        $x_1_16 = "Invoke" ascii //weight: 1
        $x_1_17 = ".Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_20
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "var1" ascii //weight: 1
        $x_1_2 = "var2" ascii //weight: 1
        $x_1_3 = "var3" ascii //weight: 1
        $x_1_4 = "projname" ascii //weight: 1
        $x_1_5 = "System.Drawing" ascii //weight: 1
        $x_1_6 = "System.Threading" ascii //weight: 1
        $x_1_7 = "get_Length" ascii //weight: 1
        $x_1_8 = "get_Size" ascii //weight: 1
        $x_1_9 = "get_Width" ascii //weight: 1
        $x_1_10 = "get_Height" ascii //weight: 1
        $x_1_11 = "get_WrappedObject" ascii //weight: 1
        $x_1_12 = "set_WrappedObject" ascii //weight: 1
        $x_1_13 = "get_Culture" ascii //weight: 1
        $x_1_14 = "set_Culture" ascii //weight: 1
        $x_1_15 = "NewLateBinding" ascii //weight: 1
        $x_1_16 = "get_X" ascii //weight: 1
        $x_1_17 = "get_Y" ascii //weight: 1
        $x_1_18 = "CreateHandle" ascii //weight: 1
        $x_1_19 = "Invoke" wide //weight: 1
        $x_1_20 = ".Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_21
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "Light" ascii //weight: 1
        $x_1_3 = "ThreadPool" ascii //weight: 1
        $x_1_4 = "var1" ascii //weight: 1
        $x_1_5 = "var2" ascii //weight: 1
        $x_1_6 = "var3" ascii //weight: 1
        $x_1_7 = "System.Drawing" ascii //weight: 1
        $x_1_8 = "projname" ascii //weight: 1
        $x_1_9 = "Guru" ascii //weight: 1
        $x_1_10 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_11 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_12 = "Activator" ascii //weight: 1
        $x_1_13 = "CreateInstance" ascii //weight: 1
        $x_1_14 = "CallByName" ascii //weight: 1
        $x_1_15 = "System.Threading" ascii //weight: 1
        $x_1_16 = "get_R" ascii //weight: 1
        $x_1_17 = "get_G" ascii //weight: 1
        $x_1_18 = "get_B" ascii //weight: 1
        $x_1_19 = "NewLateBinding" ascii //weight: 1
        $x_1_20 = "LateCall" ascii //weight: 1
        $x_1_21 = "GetPixel" ascii //weight: 1
        $x_1_22 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_22
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "var1" ascii //weight: 1
        $x_1_2 = "var2" ascii //weight: 1
        $x_1_3 = "var3" ascii //weight: 1
        $x_1_4 = "System.Drawing" ascii //weight: 1
        $x_1_5 = "get_Width" ascii //weight: 1
        $x_1_6 = "get_Length" ascii //weight: 1
        $x_1_7 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_8 = "schemafile" ascii //weight: 1
        $x_1_9 = "LoadFile" ascii //weight: 1
        $x_1_10 = "file" ascii //weight: 1
        $x_1_11 = "LoadStream" ascii //weight: 1
        $x_1_12 = "stream" ascii //weight: 1
        $x_1_13 = "System.Threading" ascii //weight: 1
        $x_1_14 = "FromBase64String" ascii //weight: 1
        $x_1_15 = "System.Reflection" ascii //weight: 1
        $x_1_16 = "SelectorX" ascii //weight: 1
        $x_1_17 = "projectname" ascii //weight: 1
        $x_1_18 = "get_WrappedObject" ascii //weight: 1
        $x_1_19 = "set_WrappedObject" ascii //weight: 1
        $x_1_20 = "System.Reflection.Emit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_23
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "System.IO" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
        $x_1_5 = "System.IO.Compression" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Encoding" ascii //weight: 1
        $x_1_8 = "Resize" ascii //weight: 1
        $x_1_9 = "XOR_Decrypt" ascii //weight: 1
        $x_1_10 = "Bitmap" ascii //weight: 1
        $x_1_11 = "System.Resources" ascii //weight: 1
        $x_1_12 = "Resource_Func" ascii //weight: 1
        $x_1_13 = "ResourceManager" ascii //weight: 1
        $x_1_14 = "Invoke" ascii //weight: 1
        $x_1_15 = "StartGame" ascii //weight: 1
        $x_1_16 = "resource_name" ascii //weight: 1
        $x_1_17 = "key_param" ascii //weight: 1
        $x_1_18 = "project_name" ascii //weight: 1
        $x_1_19 = "get_Width" ascii //weight: 1
        $x_1_20 = "get_Height" ascii //weight: 1
        $x_1_21 = "get_EntryPoint" ascii //weight: 1
        $x_1_22 = "System.Threading" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (21 of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_24
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "var1" ascii //weight: 1
        $x_1_2 = "var2" ascii //weight: 1
        $x_1_3 = "var3" ascii //weight: 1
        $x_1_4 = "System.Drawing" ascii //weight: 1
        $x_1_5 = "GeneratedCodeAttribute" ascii //weight: 1
        $x_1_6 = "get_Value" ascii //weight: 1
        $x_1_7 = "set_Value" ascii //weight: 1
        $x_1_8 = "System.Reflection" ascii //weight: 1
        $x_1_9 = "GetManifestResourceNames" ascii //weight: 1
        $x_1_10 = "MarshalByRefObject" ascii //weight: 1
        $x_1_11 = "DeflateStream" ascii //weight: 1
        $x_1_12 = "System.Security.Policy" ascii //weight: 1
        $x_1_13 = "ContainsKey" ascii //weight: 1
        $x_1_14 = "get_CurrentDomain" ascii //weight: 1
        $x_1_15 = "System.Threading" ascii //weight: 1
        $x_1_16 = "get_Length" ascii //weight: 1
        $x_1_17 = "get_Width" ascii //weight: 1
        $x_1_18 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_19 = "get_WrappedObject" ascii //weight: 1
        $x_1_20 = "set_WrappedObject" ascii //weight: 1
        $x_1_21 = "projectname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_25
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SoapName.dll" ascii //weight: 1
        $x_1_2 = "System.Runtime.CompilerServices" ascii //weight: 1
        $x_1_3 = "System.Runtime.InteropServices" ascii //weight: 1
        $x_1_4 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "Bitmap" ascii //weight: 1
        $x_1_7 = "System.Drawing" ascii //weight: 1
        $x_1_8 = "System.Threading" ascii //weight: 1
        $x_1_9 = "get_Length" ascii //weight: 1
        $x_1_10 = "get_Size" ascii //weight: 1
        $x_1_11 = "get_Width" ascii //weight: 1
        $x_1_12 = "get_Computer" ascii //weight: 1
        $x_1_13 = "get_Application" ascii //weight: 1
        $x_1_14 = "get_User" ascii //weight: 1
        $x_1_15 = "get_WebServices" ascii //weight: 1
        $x_1_16 = "get_ResourceManager" ascii //weight: 1
        $x_1_17 = "get_Culture" ascii //weight: 1
        $x_1_18 = "get_WrappedObject" ascii //weight: 1
        $x_1_19 = "My.Computer" ascii //weight: 1
        $x_1_20 = "My.Application" ascii //weight: 1
        $x_1_21 = "My.User" ascii //weight: 1
        $x_1_22 = "My.WebServices" ascii //weight: 1
        $x_1_23 = "My.Settings" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_26
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "System.IO" ascii //weight: 1
        $x_1_3 = "InverseQ" ascii //weight: 1
        $x_1_4 = "DefineMethod" ascii //weight: 1
        $x_1_5 = "CryptoStreamMode" ascii //weight: 1
        $x_1_6 = "get_BigEndianUnicode" ascii //weight: 1
        $x_1_7 = "set_Name" ascii //weight: 1
        $x_1_8 = "AssemblyName" ascii //weight: 1
        $x_1_9 = "projectname" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "ObfuscationAttribute" ascii //weight: 1
        $x_1_12 = "get_Size" ascii //weight: 1
        $x_1_13 = "System.Threading" ascii //weight: 1
        $x_1_14 = "FromBase64String" ascii //weight: 1
        $x_1_15 = "System.Drawing" ascii //weight: 1
        $x_1_16 = "BinarySearch" ascii //weight: 1
        $x_1_17 = "get_Width" ascii //weight: 1
        $x_1_18 = "get_Length" ascii //weight: 1
        $x_1_19 = "DefineLabel" ascii //weight: 1
        $x_1_20 = "GetPixel" ascii //weight: 1
        $x_1_21 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_22 = "CryptoStream" ascii //weight: 1
        $x_1_23 = "AppDomain" ascii //weight: 1
        $x_1_24 = "get_CurrentDomain" ascii //weight: 1
        $x_1_25 = "Bitmap" ascii //weight: 1
        $x_1_26 = "CreateDecryptor" ascii //weight: 1
        $x_1_27 = "get_Jonas" ascii //weight: 1
        $x_1_28 = "set_Jonas" ascii //weight: 1
        $x_1_29 = "dead codeT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_27
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "FetchUpdate" ascii //weight: 1
        $x_1_3 = "StartUpdate" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "System.Drawing" ascii //weight: 1
        $x_1_7 = "ComputeHash" ascii //weight: 1
        $x_1_8 = "get_Width" ascii //weight: 1
        $x_1_9 = "get_Length" ascii //weight: 1
        $x_1_10 = "GetPixel" ascii //weight: 1
        $x_1_11 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_12 = "get_BaseStream" ascii //weight: 1
        $x_1_13 = "CryptoStream" ascii //weight: 1
        $x_1_14 = "MemoryStream" ascii //weight: 1
        $x_1_15 = "AppDomain" ascii //weight: 1
        $x_1_16 = "get_CurrentDomain" ascii //weight: 1
        $x_1_17 = "set_Position" ascii //weight: 1
        $x_1_18 = "InvalidOperationException" ascii //weight: 1
        $x_1_19 = "InvokeMember" ascii //weight: 1
        $x_1_20 = "CryptoServiceProvider" ascii //weight: 1
        $x_1_21 = "CreateDecryptor" ascii //weight: 1
        $x_1_22 = "DebuggingModes" ascii //weight: 1
        $x_1_23 = "System.Reflection.Emit" ascii //weight: 1
        $x_1_24 = "get_EntryPoint" ascii //weight: 1
        $x_1_25 = "set_Key" ascii //weight: 1
        $x_1_26 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_27 = "get_CoreProperty" ascii //weight: 1
        $x_1_28 = "set_CoreProperty" ascii //weight: 1
        $x_1_29 = "TSP2UWUGf0UXLUIiOXAfBkglRBtlWEa6LE5jUCp2RRXxd2Z5Tl1qPWZ" ascii //weight: 1
        $x_1_30 = "dead codeT" ascii //weight: 1
        $x_1_31 = "StripAfterObfuscation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Lore_2147749242_28
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Lore!MTB"
        threat_id = "2147749242"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
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
        $x_1_9 = "{11111-22222-50001-00001}" wide //weight: 1
        $x_1_10 = "{11111-22222-50001-00002}" wide //weight: 1
        $x_10_11 = "file:///" wide //weight: 10
        $x_10_12 = "dead codeT" ascii //weight: 10
        $x_10_13 = "StripAfterObfuscation" ascii //weight: 10
        $x_10_14 = "m_useUserOverride" ascii //weight: 10
        $x_10_15 = "CreateEncryptor" ascii //weight: 10
        $x_10_16 = "ToBase64String" ascii //weight: 10
        $x_10_17 = "CipherMode" ascii //weight: 10
        $x_10_18 = "set_Mode" ascii //weight: 10
        $x_10_19 = "set_UseMachineKeyStore" ascii //weight: 10
        $x_10_20 = "CreateDecryptor" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

