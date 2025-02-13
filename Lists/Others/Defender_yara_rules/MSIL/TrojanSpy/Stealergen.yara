rule TrojanSpy_MSIL_Stealergen_MC_2147799594_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MC!MTB"
        threat_id = "2147799594"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 1e 5a 0c 00 08 02 7b ?? ?? ?? 04 [0-5] 6f ?? ?? ?? 0a 00 08 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 08 02 7b ?? ?? ?? 04 8e 69 1e 5a 6f ?? ?? ?? 0a 00 08 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 0d 00 03 73 ?? ?? ?? 0a 13 04 00 11 04 09 16 73 ?? ?? ?? 0a 13 05 00 03 8e 69 17 59 17 58 8d ?? 00 00 01 13 06 11 05 11 06 16 03 8e 69 6f ?? ?? ?? 0a 13 07 11 06 11 07 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 08 de}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "FlushFinalBlock" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "cipher" ascii //weight: 1
        $x_1_8 = "FromBase64" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
        $x_1_10 = "set_IV" ascii //weight: 1
        $x_1_11 = "set_BlockSize" ascii //weight: 1
        $x_1_12 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_MD_2147799597_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MD!MTB"
        threat_id = "2147799597"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 1e 5a 0c 00 06 02 7b ?? ?? ?? 04 [0-5] 6f ?? ?? ?? 0a 06 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 06 02 7b ?? ?? ?? 04 8e 69 1e 5a 6f ?? ?? ?? 0a 06 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0b 03 73 ?? ?? ?? 0a 0c 08 07 16 73 ?? ?? ?? 0a 0d 03 8e 69 17 59 17 58 8d ?? 00 00 01 13 04 09 11 04 16 03 8e 69 6f ?? ?? ?? 0a 13 05 11 04 11 05 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 06 de}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "FlushFinalBlock" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "cipher" ascii //weight: 1
        $x_1_8 = "FromBase64" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
        $x_1_10 = "set_IV" ascii //weight: 1
        $x_1_11 = "set_BlockSize" ascii //weight: 1
        $x_1_12 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_MF_2147806288_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MF!MTB"
        threat_id = "2147806288"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e 69 1f 0f 59 8d ?? 00 00 01 0b 02 1f 0f 07 16 02 8e 69 1f 0f 59 28 ?? ?? ?? 0a 1f 10 8d ?? 00 00 01 0c 07 8e 69 08 8e 69 59 8d ?? 00 00 01 0d 07 07 8e 69 1f 10 59 08 16 1f 10 28 ?? ?? ?? 0a 07 16 09 16 07 8e 69 08 8e 69 59 28 ?? ?? ?? 0a 73 ?? ?? ?? 06 13 04 28 ?? ?? ?? 0a 11 04 03 06 14 09 08 6f ?? ?? ?? 06 6f ?? ?? ?? 0a 13 05 de}  //weight: 1, accuracy: Low
        $x_1_2 = "get_UserName" ascii //weight: 1
        $x_1_3 = "get_Password" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "BCryptDecrypt" ascii //weight: 1
        $x_1_6 = "DecryptWithKey" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "GetAllProfiles" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "get_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_MG_2147807602_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MG!MTB"
        threat_id = "2147807602"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vsdvsdvdsvsd" ascii //weight: 1
        $x_1_2 = "Decompress" ascii //weight: 1
        $x_1_3 = "Decrypt" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "ReverseDecode" ascii //weight: 1
        $x_1_6 = "DecodeWithMatchByte" ascii //weight: 1
        $x_1_7 = "GetState" ascii //weight: 1
        $x_1_8 = "Flush" ascii //weight: 1
        $x_1_9 = "Non Obfuscated" ascii //weight: 1
        $x_1_10 = "IsCharState" ascii //weight: 1
        $x_1_11 = "DebuggableAttribute" ascii //weight: 1
        $x_1_12 = "GetTypes" ascii //weight: 1
        $x_1_13 = "ToBase64String" ascii //weight: 1
        $x_1_14 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_MA_2147808208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MA!MTB"
        threat_id = "2147808208"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 16 1b 6f ?? ?? ?? 0a 26 20 ?? ?? ?? a4 13 0b 11 08 20 ?? ?? ?? ff 5a 11 0b 61 38 ?? ?? ?? ff 07 08 6f ?? ?? ?? 06 20 ?? ?? ?? b3 13 0c 11 08 20 ?? ?? ?? ff 5a 11 0c 61 38 ?? ?? ?? ff 73 ?? ?? ?? 06 0b 1b 8d ?? ?? ?? 01 0c 20 ?? ?? ?? 50 13 0a 11 08 20 ?? ?? ?? ff 5a 11 0a 61 38 ?? ?? ?? ff 20 ?? ?? ?? da 13 0e 11 08 20 ?? ?? ?? ff 5a 11 0e 61 38 ?? ?? ?? ff 06 6f ?? ?? ?? 0a 13 07 20 ?? ?? ?? c0 38 ?? ?? ?? ff 11 06 1e 32 08 20 ?? ?? ?? d6 25 2b 06 20 ?? ?? ?? ea 25 26 38}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 62 00 69 00 74 00 62 00 75 00 63 00 6b 00 65 00 74 00 2e 00 6f 00 72 00 67 00 2f 00 63 00 68 00 65 00 67 00 65 00 33 00 2f 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 6c 00 6c 00 63 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 [0-21] 2e 00 6a 00 70 00 65 00 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 73 3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 63 68 65 67 65 33 2f 73 6f 66 74 77 61 72 65 6c 6c 63 2f 64 6f 77 6e 6c 6f 61 64 73 2f [0-21] 2e 6a 70 65 67}  //weight: 1, accuracy: Low
        $x_1_4 = "powershell" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_8 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_MH_2147808209_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MH!MTB"
        threat_id = "2147808209"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "olfaklowdo" wide //weight: 1
        $x_1_2 = "lfakdwjfm" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "Write" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_1_7 = "Encoding" ascii //weight: 1
        $x_1_8 = "MemoryStream" ascii //weight: 1
        $x_1_9 = "BlockCopy" ascii //weight: 1
        $x_1_10 = "Base64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_ME_2147808837_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.ME!MTB"
        threat_id = "2147808837"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cdn.discordapp.com/attachments" wide //weight: 1
        $x_1_2 = {11 04 11 05 11 04 11 05 91 20 a7 02 00 00 59 d2 9c 00 11 05 17 58 13 05 11 05 11 04 8e 69 fe 04 13 06 11 06 2d d9}  //weight: 1, accuracy: High
        $x_1_3 = "JKAWNFUIAIFG" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "WebResponse" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "ToString" ascii //weight: 1
        $x_1_8 = "MemoryStream" ascii //weight: 1
        $x_1_9 = "GetDomain" ascii //weight: 1
        $x_1_10 = "set_PasswordChar" ascii //weight: 1
        $x_1_11 = "GetResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_MJ_2147808843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MJ!MTB"
        threat_id = "2147808843"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$$method0x6000028-100" ascii //weight: 1
        $x_1_2 = "$$method0x600002a-100" ascii //weight: 1
        $x_1_3 = "$$method0x6000028-236" ascii //weight: 1
        $x_1_4 = "Yandex" wide //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "VirtualProtect" ascii //weight: 1
        $x_1_7 = "get_CurrentThread" ascii //weight: 1
        $x_1_8 = "IsLogging" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
        $x_1_10 = "Debugger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_ML_2147808965_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.ML!MTB"
        threat_id = "2147808965"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e4c8eaac-46c1-4a56-9961-76b33921d2ae" ascii //weight: 1
        $x_1_2 = "BUY CRYP" wide //weight: 1
        $x_1_3 = "@PulsarCrypter_bot" wide //weight: 1
        $x_1_4 = "GetDomain" ascii //weight: 1
        $x_1_5 = "rffOtOlhRBzVVqKPADYp" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "Wow64GetThreadContext" wide //weight: 1
        $x_1_9 = "GetThreadContext" wide //weight: 1
        $x_1_10 = "ReadProcessMemory" wide //weight: 1
        $x_1_11 = "WriteProcessMemory" wide //weight: 1
        $x_1_12 = "SetThreadContext" wide //weight: 1
        $x_1_13 = "DynamicDllInvoke" wide //weight: 1
        $x_1_14 = "DynamicDllModule" wide //weight: 1
        $x_1_15 = "Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_MM_2147808967_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MM!MTB"
        threat_id = "2147808967"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 31 01 00 0a 0a 73 31 01 00 0a 0b 06 72 a9 18 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 20 f4 01 00 00 28 ?? ?? ?? 0a 00 07 72 50 19 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 08 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 04 11 04 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 05 11 05 11 04 17 8d 19 00 00 01 25 16 09 a2 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06}  //weight: 1, accuracy: Low
        $x_1_2 = {6c 00 6c 00 64 00 2e 00 [0-96] 2f 00 73 00 74 00 6e 00 65 00 6d 00 68 00 63 00 61 00 74 00 74 00 61 00 2f 00 6d 00 6f 00 63 00 2e 00 70 00 70 00 61 00 64 00 72 00 6f 00 63 00 73 00 69 00 64 00 2e 00 6e 00 64 00 63 00 2f 00 2f 00 3a 00 73 00 70 00 74 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_3 = "eheyguysss" wide //weight: 1
        $x_1_4 = "StrReverse" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "Create__Instance" ascii //weight: 1
        $x_1_7 = "DebuggerHidden" ascii //weight: 1
        $x_1_8 = "get_passwd" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
        $x_1_10 = "login_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_MO_2147808969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MO!MTB"
        threat_id = "2147808969"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\racoon.ps1" wide //weight: 1
        $x_1_2 = "\\stage.ps1" wide //weight: 1
        $x_1_3 = "PowerShell data exfiltration" wide //weight: 1
        $x_1_4 = "\\remotec.ps1" wide //weight: 1
        $x_1_5 = "-Force -ErrorAction SilentlyContinue" ascii //weight: 1
        $x_1_6 = "AcquireWriterLock" ascii //weight: 1
        $x_1_7 = "ReleaseWriterLock" ascii //weight: 1
        $x_1_8 = "hostfile" ascii //weight: 1
        $x_1_9 = "toraccess" ascii //weight: 1
        $x_1_10 = "FirewallDisable" ascii //weight: 1
        $x_1_11 = "exfiltration" ascii //weight: 1
        $x_1_12 = "lateral" ascii //weight: 1
        $x_1_13 = "RunPowershell" ascii //weight: 1
        $x_1_14 = "drivers/etc/hosts" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_MQ_2147809051_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MQ!MTB"
        threat_id = "2147809051"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "951006a7-b02f-43b0-9313-f948f28ab5fa" ascii //weight: 1
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "$$method0x6000007-1" ascii //weight: 1
        $x_1_4 = "$$method0x600002a-1" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "CreateEncryptor" ascii //weight: 1
        $x_1_7 = "FlushFinalBlock" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
        $x_1_10 = "MemoryStream" ascii //weight: 1
        $x_1_11 = "IsKeyLocked" ascii //weight: 1
        $x_1_12 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_MR_2147809313_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MR!MTB"
        threat_id = "2147809313"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 1e 5a 6f ?? ?? ?? 0a 00 08 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 08 02 7b ?? ?? ?? 04 8e 69 1e 5a 6f ?? ?? ?? 0a 00 08 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {03 8e 69 17 59 17 58 8d ?? ?? ?? 01 13 06 11 05 11 06 16 03 8e 69 6f ?? ?? ?? 0a 13 07 11 06 11 07 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 08 de}  //weight: 1, accuracy: Low
        $x_1_3 = "cipher" wide //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "CreateEncryptor" ascii //weight: 1
        $x_1_8 = "FlushFinalBlock" ascii //weight: 1
        $x_1_9 = "Replace" ascii //weight: 1
        $x_1_10 = "VirtualMachineRemoteDebuggerAttach" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_2147809798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MT!MTB"
        threat_id = "2147809798"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "timerSplash_Tick" ascii //weight: 1
        $x_1_2 = "XoyFarmoshKRDaa" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "https://spacecoin.cc" wide //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "ToString" ascii //weight: 1
        $x_1_8 = "radPayDebit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_MS_2147810503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MS!MTB"
        threat_id = "2147810503"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oRM=" ascii //weight: 1
        $x_1_2 = "Append" ascii //weight: 1
        $x_1_3 = "EncryptGetPackagePropertyFlags" ascii //weight: 1
        $x_1_4 = "5duiSVc0emFFmjvFlKW6R3cL6nA" ascii //weight: 1
        $x_1_5 = "ShadowCopyDirectoriesValueCreate" ascii //weight: 1
        $x_1_6 = "43a3c7df-aa79-46aa-9e95-52c42cc8d819" ascii //weight: 1
        $x_1_7 = "Administrator\\Desktop\\Secured\\AutoRobotTradingSoftware.pdb" ascii //weight: 1
        $x_1_8 = "Skillbrains" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealergen_MU_2147810504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealergen.MU!MTB"
        threat_id = "2147810504"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 1e 5a 6f ?? ?? ?? 0a 00 07 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 07 02 7b ?? ?? ?? 04 8e 69 1e 5a 6f ?? ?? ?? 0a 00 07 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 0c 00 03 73 ?? ?? ?? 0a 0d 00 09 08 16 73 ?? ?? ?? 0a 13 04 00 03 8e 69 8d ?? ?? ?? 01 13 05 11 04 11 05 16 03 8e 69 6f ?? ?? ?? 0a 13 06 11 05 11 06}  //weight: 1, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "CD8E306CE" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "get_KeyBoard" ascii //weight: 1
        $x_1_7 = "Debug" ascii //weight: 1
        $x_1_8 = "get_CapsLock" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

