rule Trojan_MSIL_Lausivloader_WEQ_2147975779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.WEQ!MTB"
        threat_id = "2147975779"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 00 00 00 02 00 00 01 57 ff b7 3f 09 1f 00 00 00 fa a5 33 00 16 00 00 01 00 00 00 9a 01 00 00 66 07 00 00 ff 0a 00 00 e2 21 00 00 5d 0a 00 00 c2 00 00 00 4e 05 00 00 08 03 00 00 6c 06 00 00 ad 01 00 00 02 00 00 00 07 00 00 00 04 00 00 00 1a 02 00 00 05 00 00 00 07 00 00 00 ac 00 00 00 05 03 00 00 cf 04 00 00 bd 00 00 00 08 00 00 00 d6 00 00 00 2a 00 00 00 02 00 00 00 01 00 00 00 0a 00 00 00 01 00 00 00 88 00 00 00 46 00 00 00 7c 00 00 00 1c 00 00 00}  //weight: 4, accuracy: High
        $x_3_2 = "OtnmpxnddVnptbN" ascii //weight: 3
        $x_1_3 = "Microsoft.Win32.TaskScheduler_protected.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_WZQ_2147976216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.WZQ!MTB"
        threat_id = "2147976216"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 00 00 00 02 00 00 01 57 ff b7 3f 09 1f 00 00 00 fa a5 33 00 16 00 00 01 00 00 00 92 01 00 00 b4 01 00 00 4e 05 00 00 1c 0b 00 00 3a 0a 00 00 c2 00 00 00 2a 05 00 00 08 03 00 00 6b 06 00 00 ad 01 00 00 02 00 00 00 07 00 00 00 04 00 00 00 11 02 00 00 05 00 00 00 07 00 00 00 ac 00 00 00 05 03 00 00 cf 04 00 00 bd 00 00 00 08 00 00 00 d6 00 00 00 2a 00 00 00 02 00 00 00 01 00 00 00 0a 00 00 00 03 00 00 00 87 00 00 00 46 00 00 00 7c 00 00 00 1c 00 00 00}  //weight: 4, accuracy: High
        $x_3_2 = "OtnmpxnddVnptbN" ascii //weight: 3
        $x_1_3 = "Microsoft.Win32.TaskScheduler_protected.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_WRN_2147976248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.WRN!MTB"
        threat_id = "2147976248"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "OtnmpxnddVnptbN" ascii //weight: 10
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "StrReverse" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "CreateEncryptor" ascii //weight: 1
        $x_1_7 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_8 = "BootTrigger" ascii //weight: 1
        $x_1_9 = "Microsoft.Win32.TaskScheduler_protected.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_WVN_2147976324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.WVN!MTB"
        threat_id = "2147976324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "OtnmpxnddVnptbN" ascii //weight: 10
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "StrReverse" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_8 = "BootTrigger" ascii //weight: 1
        $x_1_9 = "Microsoft.Win32.TaskScheduler_protected.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_W_2147977060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.W!MTB"
        threat_id = "2147977060"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "OtnmpxnddVnptbN" ascii //weight: 10
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "StrReverse" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_8 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_WQ_2147977541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.WQ!MTB"
        threat_id = "2147977541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "OtnmpxnddVnptbN" ascii //weight: 10
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_1_3 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_4 = "SetThreadContext" ascii //weight: 1
        $x_1_5 = "CreateProcess" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
        $x_1_9 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_10 = "BootTrigger" ascii //weight: 1
        $x_1_11 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_MA_2147977877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.MA!MTB"
        threat_id = "2147977877"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_2_2 = "trailer" ascii //weight: 2
        $x_2_3 = "praia" ascii //weight: 2
        $x_2_4 = "casa" ascii //weight: 2
        $x_1_5 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_6 = "SetThreadContext" ascii //weight: 1
        $x_1_7 = "CreateProcess" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateDecryptor" ascii //weight: 1
        $x_1_11 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_12 = "BootTrigger" ascii //weight: 1
        $x_1_13 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_MC_2147977943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.MC!MTB"
        threat_id = "2147977943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_2_2 = "VerificarMinutos" ascii //weight: 2
        $x_2_3 = "cpiNcystvbmomsM" ascii //weight: 2
        $x_2_4 = "vzuwobbatvffzyN" ascii //weight: 2
        $x_1_5 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_6 = "SetThreadContext" ascii //weight: 1
        $x_1_7 = "CreateProcess" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateDecryptor" ascii //weight: 1
        $x_1_11 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_12 = "BootTrigger" ascii //weight: 1
        $x_1_13 = "SendEmail" ascii //weight: 1
        $x_1_14 = "Rijndael" ascii //weight: 1
        $x_1_15 = "VirtualAllocEx" ascii //weight: 1
        $x_1_16 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_DC_2147978318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.DC!MTB"
        threat_id = "2147978318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_2_2 = "VerificarMinutos" ascii //weight: 2
        $x_2_3 = "cpiNcystvbmomsM" ascii //weight: 2
        $x_2_4 = "vzuwobbatvffzyN" ascii //weight: 2
        $x_2_5 = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"[System.Net.WebClient]::New().DownloadFile('" ascii //weight: 2
        $x_1_6 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_7 = "SetThreadContext" ascii //weight: 1
        $x_1_8 = "CreateProcess" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_1_11 = "CreateDecryptor" ascii //weight: 1
        $x_1_12 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_13 = "BootTrigger" ascii //weight: 1
        $x_1_14 = "SendEmail" ascii //weight: 1
        $x_1_15 = "get_UserPassword" ascii //weight: 1
        $x_1_16 = "vboxservice" ascii //weight: 1
        $x_1_17 = "VirtualAllocEx" ascii //weight: 1
        $x_1_18 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_UC_2147978617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.UC!MTB"
        threat_id = "2147978617"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_3_2 = "HackForums.gigajew" ascii //weight: 3
        $x_1_3 = "System.Net.Http" ascii //weight: 1
        $x_1_4 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_5 = "SetThreadContext" ascii //weight: 1
        $x_1_6 = "CreateProcess" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
        $x_1_10 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_11 = "VirtualAllocEx" ascii //weight: 1
        $x_1_12 = "GetThreadContext" ascii //weight: 1
        $x_1_13 = "ResumeThread" ascii //weight: 1
        $x_1_14 = "CloseHandle" ascii //weight: 1
        $x_1_15 = "get_UserName" ascii //weight: 1
        $x_1_16 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_UZ_2147978880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.UZ!MTB"
        threat_id = "2147978880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "006#5o6&qr1V" ascii //weight: 6
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_2_3 = "DescriptografarEntradas" ascii //weight: 2
        $x_2_4 = "ConfiguracaoDescriptografia" ascii //weight: 2
        $x_1_5 = "System.Net.Http" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_9 = "get_UserName" ascii //weight: 1
        $x_1_10 = "Protect" ascii //weight: 1
        $x_1_11 = "Process" ascii //weight: 1
        $x_1_12 = "Memory" ascii //weight: 1
        $x_1_13 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_UZ_2147978880_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.UZ!MTB"
        threat_id = "2147978880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "006#5o6&qr1V" ascii //weight: 6
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_1_3 = "System.Net.Http" ascii //weight: 1
        $x_1_4 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_5 = "SetThreadContext" ascii //weight: 1
        $x_1_6 = "CreateProcess" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
        $x_1_10 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_11 = "VirtualAllocEx" ascii //weight: 1
        $x_1_12 = "GetThreadContext" ascii //weight: 1
        $x_1_13 = "ResumeThread" ascii //weight: 1
        $x_1_14 = "CloseHandle" ascii //weight: 1
        $x_1_15 = "get_UserName" ascii //weight: 1
        $x_1_16 = "Virtual" ascii //weight: 1
        $x_1_17 = "Protect" ascii //weight: 1
        $x_1_18 = "_TASK_LOGON_TYPE" ascii //weight: 1
        $x_1_19 = "Debugger Detected" ascii //weight: 1
        $x_1_20 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_UR_2147979458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.UR!MTB"
        threat_id = "2147979458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "006#5o6&qr1V" ascii //weight: 6
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_2_3 = "DescriptografarEntradas" ascii //weight: 2
        $x_1_4 = "Win32.RMP" ascii //weight: 1
        $x_1_5 = "Met_" ascii //weight: 1
        $x_1_6 = "Cls_" ascii //weight: 1
        $x_1_7 = "System.Net.Http" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
        $x_1_10 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_11 = "TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD" ascii //weight: 1
        $x_1_12 = "get_UserName" ascii //weight: 1
        $x_1_13 = "Virtual" ascii //weight: 1
        $x_1_14 = "Protect" ascii //weight: 1
        $x_1_15 = "Alloc" ascii //weight: 1
        $x_1_16 = "Write" ascii //weight: 1
        $x_1_17 = "Process" ascii //weight: 1
        $x_1_18 = "Memory" ascii //weight: 1
        $x_1_19 = "ResourceA" ascii //weight: 1
        $x_1_20 = "_TASK_LOGON_TYPE" ascii //weight: 1
        $x_1_21 = "Debugger Detected" ascii //weight: 1
        $x_1_22 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_MZ_2147979654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.MZ!MTB"
        threat_id = "2147979654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "006#5o6&qr1V" ascii //weight: 6
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_2_3 = "VerificarMinutos" ascii //weight: 2
        $x_1_4 = "System.Net.Http" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_7 = "get_UserName" ascii //weight: 1
        $x_1_8 = "VirtualAllocEx" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_11 = "SetThreadContext" ascii //weight: 1
        $x_1_12 = "GetThreadContext" ascii //weight: 1
        $x_1_13 = "ResumeThread" ascii //weight: 1
        $x_1_14 = "CloseHandle" ascii //weight: 1
        $x_1_15 = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand" ascii //weight: 1
        $x_1_16 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_MZ_2147979654_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.MZ!MTB"
        threat_id = "2147979654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_4_2 = "Win32.RMP" ascii //weight: 4
        $x_2_3 = "ModernInjection" ascii //weight: 2
        $x_2_4 = "nuhf0Ha3GK" ascii //weight: 2
        $x_2_5 = "ikOeAKscLmWyGnfhjmK" ascii //weight: 2
        $x_2_6 = "CreateSuspendedProcess" ascii //weight: 2
        $x_2_7 = "WriteHeaders" ascii //weight: 2
        $x_1_8 = "System.Net.Http" ascii //weight: 1
        $x_1_9 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_10 = "SetThreadContext" ascii //weight: 1
        $x_1_11 = "CreateProcess" ascii //weight: 1
        $x_1_12 = "WriteProcessMemory" ascii //weight: 1
        $x_1_13 = "FromBase64String" ascii //weight: 1
        $x_1_14 = "CreateDecryptor" ascii //weight: 1
        $x_1_15 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_16 = "VirtualAllocEx" ascii //weight: 1
        $x_1_17 = "GetThreadContext" ascii //weight: 1
        $x_1_18 = "ResumeThread" ascii //weight: 1
        $x_1_19 = "CloseHandle" ascii //weight: 1
        $x_1_20 = "get_UserName" ascii //weight: 1
        $x_1_21 = "Virtual" ascii //weight: 1
        $x_1_22 = "Protect" ascii //weight: 1
        $x_1_23 = "is tampered" ascii //weight: 1
        $x_1_24 = "_TASK_LOGON_TYPE" ascii //weight: 1
        $x_1_25 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_EZ_2147979762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.EZ!MTB"
        threat_id = "2147979762"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "006#5o6&qr1V" ascii //weight: 6
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_2_3 = "DescriptografarEntradas" ascii //weight: 2
        $x_1_4 = "Win32.RMP" ascii //weight: 1
        $x_1_5 = "Met_" ascii //weight: 1
        $x_1_6 = "Cls_" ascii //weight: 1
        $x_1_7 = "System.Net.Http" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
        $x_1_10 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_11 = "TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD" ascii //weight: 1
        $x_1_12 = "get_UserName" ascii //weight: 1
        $x_1_13 = "Virtual" ascii //weight: 1
        $x_1_14 = "Protect" ascii //weight: 1
        $x_1_15 = "Alloc" ascii //weight: 1
        $x_1_16 = "Write" ascii //weight: 1
        $x_1_17 = "Process" ascii //weight: 1
        $x_1_18 = "Memory" ascii //weight: 1
        $x_1_19 = "ResourceA" ascii //weight: 1
        $x_1_20 = "_TASK_LOGON_TYPE" ascii //weight: 1
        $x_1_21 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_EZ_2147979762_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.EZ!MTB"
        threat_id = "2147979762"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_2_2 = "DescriptografarEntradas" ascii //weight: 2
        $x_2_3 = "ConfiguracaoDescriptografia" ascii //weight: 2
        $x_2_4 = "ModernInjection" ascii //weight: 2
        $x_2_5 = "CreateSuspendedProcess" ascii //weight: 2
        $x_2_6 = "ProcessLoaderModern" ascii //weight: 2
        $x_2_7 = "Win32.RMP" ascii //weight: 2
        $x_1_8 = "System.Net.Http" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateDecryptor" ascii //weight: 1
        $x_1_11 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_12 = "TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD" ascii //weight: 1
        $x_1_13 = "get_UserName" ascii //weight: 1
        $x_1_14 = "VirtualAllocEx" ascii //weight: 1
        $x_1_15 = "Protect" ascii //weight: 1
        $x_1_16 = "WriteProcessMemory" ascii //weight: 1
        $x_1_17 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_18 = "SetThreadContext" ascii //weight: 1
        $x_1_19 = "CreateProcessW" ascii //weight: 1
        $x_1_20 = "_TASK_LOGON_TYPE" ascii //weight: 1
        $x_1_21 = "GetThreadContext" ascii //weight: 1
        $x_1_22 = "ResumeThread" ascii //weight: 1
        $x_1_23 = "CloseHandle" ascii //weight: 1
        $x_1_24 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_RZ_2147980240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.RZ!MTB"
        threat_id = "2147980240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "006#5o6&qr1V" ascii //weight: 6
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_2_3 = "DescriptografarEntradas" ascii //weight: 2
        $x_2_4 = "ConfiguracaoDescriptografia" ascii //weight: 2
        $x_1_5 = "System.Net.Http" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_8 = "get_UserName" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_RZ_2147980240_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.RZ!MTB"
        threat_id = "2147980240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "006#5o6&qr1V" ascii //weight: 6
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_2_3 = "DescriptografarEntradas" ascii //weight: 2
        $x_2_4 = "ConfiguracaoDescriptografia" ascii //weight: 2
        $x_1_5 = "Win32.RMP" ascii //weight: 1
        $x_1_6 = "System.Net.Http" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
        $x_1_9 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_10 = "TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD" ascii //weight: 1
        $x_1_11 = "get_UserName" ascii //weight: 1
        $x_1_12 = "Virtual" ascii //weight: 1
        $x_1_13 = "Protect" ascii //weight: 1
        $x_1_14 = "Alloc" ascii //weight: 1
        $x_1_15 = "Write" ascii //weight: 1
        $x_1_16 = "Process" ascii //weight: 1
        $x_1_17 = "Memory" ascii //weight: 1
        $x_1_18 = "ResourceA" ascii //weight: 1
        $x_1_19 = "_TASK_LOGON_TYPE" ascii //weight: 1
        $x_1_20 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_KK_2147980576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.KK!MTB"
        threat_id = "2147980576"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ConfiguracaoDescriptografia" ascii //weight: 5
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_3_3 = "DescriptografarEntradas" ascii //weight: 3
        $x_2_4 = "006#5o6&qr1V" wide //weight: 2
        $x_1_5 = "Win32.RMP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_VZ_2147980666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.VZ!MTB"
        threat_id = "2147980666"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "Win32.RMP" ascii //weight: 6
        $x_4_2 = "ChaveSecretaGlobal" ascii //weight: 4
        $x_2_3 = "DescriptografarEntradas" ascii //weight: 2
        $x_2_4 = "ConfiguracaoDescriptografia" ascii //weight: 2
        $x_1_5 = "System.Net.Http" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_9 = "TASK_LOGON INTERACTIVE TOKEN OR PASSWORD" ascii //weight: 1
        $x_1_10 = "get_UserName" ascii //weight: 1
        $x_1_11 = "Protect" ascii //weight: 1
        $x_1_12 = "Process" ascii //weight: 1
        $x_1_13 = "Memory" ascii //weight: 1
        $x_1_14 = "TASK LOGON_TYPE" ascii //weight: 1
        $x_1_15 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_TZ_2147981066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.TZ!MTB"
        threat_id = "2147981066"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "Amoeba" ascii //weight: 6
        $x_4_2 = "Cadeira" ascii //weight: 4
        $x_4_3 = "$eea0cbc0-6200-42c6-a276-2327dbd88405" ascii //weight: 4
        $x_1_4 = "Virtual" ascii //weight: 1
        $x_1_5 = "Alloc" ascii //weight: 1
        $x_1_6 = "Write" ascii //weight: 1
        $x_1_7 = "Process" ascii //weight: 1
        $x_1_8 = "Memory" ascii //weight: 1
        $x_1_9 = "Protect" ascii //weight: 1
        $x_1_10 = "Close" ascii //weight: 1
        $x_1_11 = "Handle" ascii //weight: 1
        $x_1_12 = "kernel" ascii //weight: 1
        $x_1_13 = "32.dll" ascii //weight: 1
        $x_1_14 = "ResourceA" ascii //weight: 1
        $x_1_15 = "get_UserName" ascii //weight: 1
        $x_1_16 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_17 = "System.Net.Http" ascii //weight: 1
        $x_1_18 = "CreateDecryptor" ascii //weight: 1
        $x_1_19 = "Debugger Detected" ascii //weight: 1
        $x_1_20 = "FromBase64String" ascii //weight: 1
        $x_1_21 = "TASK_TRIGGER_REGISTRATION" ascii //weight: 1
        $x_1_22 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_JZ_2147981202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.JZ!MTB"
        threat_id = "2147981202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "006#5o6&qr1V" ascii //weight: 6
        $x_6_2 = "Amoeba" ascii //weight: 6
        $x_4_3 = "Cadeira" ascii //weight: 4
        $x_4_4 = "$eea0cbc0-6200-42c6-a276-2327dbd88405" ascii //weight: 4
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "TASK_TRIGGER_REGISTRATION" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "get_UserName" ascii //weight: 1
        $x_1_9 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_10 = "System.Net.Http" ascii //weight: 1
        $x_1_11 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lausivloader_YZ_2147981270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lausivloader.YZ!MTB"
        threat_id = "2147981270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lausivloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "Amoeba" ascii //weight: 6
        $x_4_2 = "Cadeira" ascii //weight: 4
        $x_4_3 = "$eea0cbc0-6200-42c6-a276-2327dbd88405" ascii //weight: 4
        $x_1_4 = "Virtual" ascii //weight: 1
        $x_1_5 = "Alloc" ascii //weight: 1
        $x_1_6 = "Write" ascii //weight: 1
        $x_1_7 = "Process" ascii //weight: 1
        $x_1_8 = "Memory" ascii //weight: 1
        $x_1_9 = "Protect" ascii //weight: 1
        $x_1_10 = "Close" ascii //weight: 1
        $x_1_11 = "Handle" ascii //weight: 1
        $x_1_12 = "kernel" ascii //weight: 1
        $x_1_13 = "32.dll" ascii //weight: 1
        $x_1_14 = "ResourceA" ascii //weight: 1
        $x_1_15 = "get_UserName" ascii //weight: 1
        $x_1_16 = "RegisterTaskDefinition" ascii //weight: 1
        $x_1_17 = "System.Net.Http" ascii //weight: 1
        $x_1_18 = "CreateDecryptor" ascii //weight: 1
        $x_1_19 = "FromBase64String" ascii //weight: 1
        $x_1_20 = "TASK_TRIGGER_REGISTRATION" ascii //weight: 1
        $x_1_21 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

