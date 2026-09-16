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

