rule Trojan_MSIL_Njrat_DB_2147783078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.DB!MTB"
        threat_id = "2147783078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 07 11 06 11 07 28 ?? ?? ?? 0a 0a 06 28 ?? ?? ?? 0a 13 09 11 09 28 ?? ?? ?? 0a 13 08 28 ?? ?? ?? 0a 11 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 14 14 6f ?? ?? ?? 0a 26 72 ?? ?? ?? 70 13 05 72 ?? ?? ?? 70 0b 72 ?? ?? ?? 70 0c 28 ?? ?? ?? 0a 11 05 17 17 8d ?? ?? ?? 01 13 0a 11 0a 16 11 08 a2 11 0a}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MB_2147816623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MB!MTB"
        threat_id = "2147816623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 09 09 6f ?? ?? ?? 0a 1b 6a da 6f ?? ?? ?? 0a 00 09 07 16 1a 6f ?? ?? ?? 0a 26 07 16 28 ?? ?? ?? 0a 13 04 09 16 6a 6f ?? ?? ?? 0a 00 11 04 17 da 17 d6 17 da 17 d6 8d ?? ?? ?? 01 0a 08 06 16 11 04 6f ?? ?? ?? 0a 26 08 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 00 06 13 05 2b 00 11 05 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "shutdowncomputer" wide //weight: 1
        $x_1_3 = "DisableCMD" wide //weight: 1
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
        $x_1_5 = "GetTempPath" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "Sleep" ascii //weight: 1
        $x_1_8 = "taskkill /F /IM PING.EXE" wide //weight: 1
        $x_1_9 = "DownloadFile" ascii //weight: 1
        $x_1_10 = "MemoryStream" ascii //weight: 1
        $x_1_11 = "cmd.exe /k ping 0 & del" wide //weight: 1
        $x_1_12 = "netsh firewall delete allowedprogram" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MC_2147819023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MC!MTB"
        threat_id = "2147819023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 02 8e 69 13 08 12 08 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0c 12 02 28 ?? ?? ?? 06 0d 07 09 16 09 8e 69 6f ?? ?? ?? 0a 00 07 02 16 02 8e 69 6f ?? ?? ?? 0a 00 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 16 07 6f ?? ?? ?? 0a b7 16 6f ?? ?? ?? 0a 26 07 6f ?? ?? ?? 0a 00 00 de 09}  //weight: 1, accuracy: Low
        $x_1_2 = {06 b5 0b 1f 64 28 ?? ?? ?? 0a 0c 1f 64 0d 14 13 04 07 12 02 09 12 04 1f 64 28 ?? ?? ?? 06 16 fe 01 13 06 11 06 2d 03 00 2b 1a 06 17 d6 0a 06 1a fe 02 16 fe 01 13 06 11 06 2d 03 00 2b 0b 00 17 13 06 2b bb}  //weight: 1, accuracy: Low
        $x_1_3 = "cmd.exe /C Y /N /D Y /T 1 & Del" wide //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "DecompressGzip" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "OSFullName" ascii //weight: 1
        $x_1_9 = "SearchForCam" ascii //weight: 1
        $x_1_10 = "StringToBase64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MD_2147819024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MD!MTB"
        threat_id = "2147819024"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0d 09 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "stopme" ascii //weight: 1
        $x_1_3 = "MyAntiProcess" ascii //weight: 1
        $x_1_4 = "Launch_crypt" ascii //weight: 1
        $x_1_5 = "Decrypt_File" ascii //weight: 1
        $x_1_6 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_7 = "Reverse" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "ReadProcessMemory" ascii //weight: 1
        $x_1_10 = "SuspendThread" ascii //weight: 1
        $x_1_11 = "CreateDecryptor" ascii //weight: 1
        $x_1_12 = "FromBase64String" ascii //weight: 1
        $x_1_13 = "StartSlowloris" ascii //weight: 1
        $x_1_14 = "get_ShiftKeyDown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MG_2147819715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MG!MTB"
        threat_id = "2147819715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 03 09 6f ?? ?? ?? 0a 13 06 12 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 03 09 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 28 ?? ?? ?? 0a 16 fe 01 fe 01 13 05 11 05 2c 1e 07 03 09 6f ?? ?? ?? 0a 13 06 12 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 2b 0e 07 03 09 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 00 09 17 d6 0d 09 08 3e 3e}  //weight: 10, accuracy: Low
        $x_1_2 = "GetFolderPath" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_NE_2147827663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.NE!MTB"
        threat_id = "2147827663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 95 58 20 ?? 00 00 00 5f 95 61 28 ?? 00 00 06 9c 00 11 08 17 58 13 08 11 08 11 05 8e 69 fe 04 13 09 11 09 2d 9b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_NEA_2147828739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.NEA!MTB"
        threat_id = "2147828739"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mpgtzyskrgvavisw" wide //weight: 1
        $x_1_2 = "Qvisfqkf.bmp" wide //weight: 1
        $x_1_3 = "Ouypajv2" ascii //weight: 1
        $x_1_4 = "Psnljxqb.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_NEB_2147828748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.NEB!MTB"
        threat_id = "2147828748"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 36 11 36 16 72 ?? 02 00 70 a2 11 36 17 7e 1b 00 00 04 a2 11 36 18 06 17 9a a2 11 36 19 7e 1b 00 00 04 a2 11 36 1a 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_NEC_2147828932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.NEC!MTB"
        threat_id = "2147828932"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 16 06 6f 21 00 00 0a 6f 54 00 00 0a 6f 55 00 00 0a 28 56 00 00 0a 28 35 00 00 0a 0d 11 04 17 d6 13 04 11 04 11 05 31 d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_NEG_2147829900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.NEG!MTB"
        threat_id = "2147829900"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "nAN#t9R" ascii //weight: 3
        $x_3_2 = "zvaWv7sk" ascii //weight: 3
        $x_3_3 = "vsVllxJ" ascii //weight: 3
        $x_2_4 = "E{0lTiNg" ascii //weight: 2
        $x_1_5 = "Windows.exe" ascii //weight: 1
        $x_1_6 = "mkhWfe" ascii //weight: 1
        $x_1_7 = "zxa4vGs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_ABY_2147833103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.ABY!MTB"
        threat_id = "2147833103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 11 05 02 11 05 91 11 04 61 09 08 91 61 b4 9c 08 03 6f 0d 00 00 0a 17 da fe 01 13 07 11 07 2c 04 16 0c 2b 05 00 08 17 d6 0c 00 11 05 17 d6 13 05 11 05 11 06 13 08 11 08 31 c5}  //weight: 5, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "oanseeeeee" wide //weight: 1
        $x_1_4 = "zwoaaaeeeee" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MH_2147842620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MH!MTB"
        threat_id = "2147842620"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 00 11 04 17 d6 13 04 11 04 09 8e 69 fe 04 13 06 11 06 2d c9 07 6f ?? ?? ?? 0a 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "HexDecrypt" ascii //weight: 1
        $x_1_3 = "75901912-a909-4716-9858-ebea96cc5899" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_PSIX_2147844775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.PSIX!MTB"
        threat_id = "2147844775"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 09 6f 4f 00 00 0a 28 ?? ?? ?? 0a 9c 20 08 00 00 00 fe 0e 0c 00 38 32 ff ff ff 11 06 11 05 17 73 ?? ?? ?? 0a 13 07 20 0c 00 00 00 fe 0e 0c 00 38 18 ff ff ff 11 07 6f ?? ?? ?? 0a 20 15 00 00 00 38 0b ff ff ff 11 04 07 08 6f 81 00 00 0a 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_RPY_2147848022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.RPY!MTB"
        threat_id = "2147848022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 6f 24 00 00 9d 06 1a 20 f7 29 00 00 9d 06 16 20 79 1b 00 00 9d 06 1d 20 18 0f 00 00 9d 06 17 20 d0 2b 00 00 9d 06 19 20 59 3f 00 00 9d 06 1b 20 ab 38 00 00 9d 06 1c 20 c9 04 00 00 9d 20 be 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_RPY_2147848022_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.RPY!MTB"
        threat_id = "2147848022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 0a 73 20 00 00 0a 0b 07 28 21 00 00 0a 02 6f 22 00 00 0a 6f 23 00 00 0a 0a 07 6f 24 00 00 0a 06 2a}  //weight: 1, accuracy: High
        $x_1_2 = "clash njrat" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "ToString" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_RPY_2147848022_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.RPY!MTB"
        threat_id = "2147848022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Njrat 0.7" wide //weight: 1
        $x_1_2 = "cmd.exe /c ping 0 -n 2 & del" wide //weight: 1
        $x_1_3 = "www.upload.ee" wide //weight: 1
        $x_1_4 = "schtasks /create /sc minute /mo 1 /tn Server /tr " wide //weight: 1
        $x_1_5 = "[ScrollLock]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MAAE_2147848147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MAAE!MTB"
        threat_id = "2147848147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 04 11 04 08 6f ?? 00 00 0a 00 11 04 04 6f ?? 00 00 0a 00 11 04 05 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 0a 06 02 16 02 8e b7 6f ?? 00 00 0a 0d 11 04 6f 4a 00 00 0a 00 09 13 05 2b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_RPX_2147851169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.RPX!MTB"
        threat_id = "2147851169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2.tcp.eu.ngrok.io" wide //weight: 1
        $x_1_2 = "SpyTheSpy" wide //weight: 1
        $x_1_3 = "smsniff" wide //weight: 1
        $x_1_4 = "processhacker" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "netsh firewall add allowedprogram" wide //weight: 1
        $x_1_7 = "GetKeyboardState" ascii //weight: 1
        $x_1_8 = "GZipStream" ascii //weight: 1
        $x_1_9 = "Replace" ascii //weight: 1
        $x_1_10 = "LateCall" ascii //weight: 1
        $x_1_11 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_SPT_2147851809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.SPT!MTB"
        threat_id = "2147851809"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 14 fe 01 16 fe 01 2d 02 de 51 07 6f ?? ?? ?? 0a d4 8d 13 00 00 01 0c 07 08 16 08 8e 69 6f ?? ?? ?? 0a 26 08 28 ?? ?? ?? 0a 72 13 00 00 70 6f ?? ?? ?? 0a 28 01 00 00 06 0c 08}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MBID_2147888932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MBID!MTB"
        threat_id = "2147888932"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 05 02 11 05 91 08 61 06 07 91 61 b4 9c 07 03 6f ?? 00 00 0a 17 da fe 01 13 07 11 07 2c 04 16 0b 2b 05}  //weight: 1, accuracy: Low
        $x_1_2 = "9fb6bf66e97a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MBIF_2147889026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MBIF!MTB"
        threat_id = "2147889026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 64 73 66 64 73 66 73 64 64 73 66 00 61 62 64 6f 00 65 77 71 65 77 71 77 65 71 77 65 71 00 64 73 61 64 73 61 64 61 73 64 73 61}  //weight: 1, accuracy: High
        $x_1_2 = "ConsoleApplication1.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MBEH_2147895337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MBEH!MTB"
        threat_id = "2147895337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 7a 00 76 00 43 00 30 00 44 00 63 00 35 00 65 00 3f 00 3f 00 3f 00 3f 00 3f 00 3f 00 3f 00 3f 00 3e 00 3c 00 3e 00 3c 00 3e 00 3c 00 3e 00 3c 00 3e 00 3c 00 3e 00 3c 00 3e 00 3c 00 3e 00 3c 00 3f 00 3f 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = {35 00 79 00 4e 00 66 00 35 00 5a 00 41 00 54 00 54 00 6e 00 6f 00 4f 00 4d 00 74 00 2b 00 61 00 37 00 50 00 70 00 2f 00 37 00 36 00 30 00 53 00 59 00 2f 00 59 00 64 00 75 00 42 00 34 00 6e 00 4d 00 2b 00 4c 00 42}  //weight: 1, accuracy: High
        $x_1_3 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 00 0f 6e 00 6f 00 74 00 68 00 69 00 6e 00 67}  //weight: 1, accuracy: High
        $x_1_4 = "md5Decrypt" ascii //weight: 1
        $x_1_5 = "MD5CryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MMC_2147899062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MMC!MTB"
        threat_id = "2147899062"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 28 02 00 00 06 13 05 11 05 28 05 00 00 06 13 06 11 06 7e 01 00 00 04 28 04 00 00 06 13 07}  //weight: 2, accuracy: High
        $x_1_2 = "Win.exe" ascii //weight: 1
        $x_1_3 = "WcfService1.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Njrat_DA_2147899388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.DA!MTB"
        threat_id = "2147899388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$$$$$$$i$$$$n$$$v$$$$o$$$k$$$e$$$$$$$$$" ascii //weight: 10
        $x_1_2 = "WindowsApplication" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "Activator" ascii //weight: 1
        $x_1_5 = "Convert" ascii //weight: 1
        $x_1_6 = "EntryPoint" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MVT_2147900673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MVT!MTB"
        threat_id = "2147900673"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 02 28 0f 00 00 06 0d de 16}  //weight: 2, accuracy: High
        $x_1_2 = {48 65 61 72 74 [0-15] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_LS_2147901673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.LS!MTB"
        threat_id = "2147901673"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 16 fe 01 5f 07 17 5f 17 fe 01 5f ?? ?? ?? ?? ?? 16 fe 01 06 16 fe 01 16 fe 01 5f 07 17 5f 17 fe 01 5f 60 0c 11 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_AMBE_2147903245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.AMBE!MTB"
        threat_id = "2147903245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 14 fe 01 38 ?? ?? ?? ?? 07 73 ?? 00 00 0a 21 ?? ?? ?? ?? ?? ?? ?? ?? 28 ?? 00 00 0a 21 ?? ?? ?? ?? ?? ?? ?? ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 16 73 ?? 00 00 0a 16 73 ?? 00 00 0a 13 04 17 2b a5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_NC_2147903523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.NC!MTB"
        threat_id = "2147903523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 20}  //weight: 5, accuracy: Low
        $x_5_2 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 2c}  //weight: 5, accuracy: Low
        $x_5_3 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 23}  //weight: 5, accuracy: Low
        $x_5_4 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 24}  //weight: 5, accuracy: Low
        $x_5_5 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 27}  //weight: 5, accuracy: Low
        $x_5_6 = {11 0c 25 17 58 13 0c 93 11 ?? 61 60 13 07 11 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Njrat_NB_2147904508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.NB!MTB"
        threat_id = "2147904508"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 6f 91 61 1f ?? 5f 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MBZQ_2147905237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MBZQ!MTB"
        threat_id = "2147905237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TVqQ&&M&&&&E&&&&//8&&Lg" wide //weight: 1
        $x_1_2 = "EntryPoint" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MBZY_2147907707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MBZY!MTB"
        threat_id = "2147907707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 dc 05 dc 05 5a 00 dc 05 dc 05 90 00 dc 05 dc 05 00 00 dc 05 dc 05 03 00 dc 05 dc 05 00 00 dc 05 dc 05 00 00 dc 05 dc 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_PLIKH_2147931706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.PLIKH!MTB"
        threat_id = "2147931706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 00 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 13 04 11 04 13 05 11 05 74 ?? 00 00 1b 13 06 2b 00 11 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_PLIWH_2147932350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.PLIWH!MTB"
        threat_id = "2147932350"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 00 09 04 6f ?? 00 00 0a 00 09 05 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 13 04 09 6f ?? 00 00 0a 00 11 04 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_PWA_2147935793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.PWA!MTB"
        threat_id = "2147935793"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 06 4a 08 06 4a 91 02 06 4a 1f 10 5d 91 61 9c 06 06 4a 17 d6}  //weight: 5, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_PHN_2147936673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.PHN!MTB"
        threat_id = "2147936673"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 05 11 04 6f ?? 00 00 0a 0d 08 09 28 ?? 00 00 0a 07 da 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 11 04 17 d6 13 04 00 11 04 11 06 fe 04 13 07 11 07 2d ca 08 28 ?? 00 00 0a 0c 08 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "Dark_decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_ZOV_2147941417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.ZOV!MTB"
        threat_id = "2147941417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 11 04 91 0d 07 11 04 07 11 05 91 9c 07 11 05 09 9c 07 11 04 91 07 11 05 91 58 20 00 01 00 00 5d 13 07 02 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 07 11 07 91 61 d2 81 ?? 00 00 01 11 06 17 58 13 06 11 06 02 16 6f ?? 00 00 0a 32 8f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_ZNQ_2147948005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.ZNQ!MTB"
        threat_id = "2147948005"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 26 0c 08 0a 1f 0a 2b 38 2b ae 08 11 05 02 11 05 91 09 61 11 04 07 91 61 b4 9c 07 03 6f ?? 00 00 0a 25 26 17 da fe 01 13 07 11 07 2c 49}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_EHVV_2147949719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.EHVV!MTB"
        threat_id = "2147949719"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 5e 26 16 13 0a 2b 2b 11 05 11 0a 8f 0d 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Njrat_MCG_2147951587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Njrat.MCG!MTB"
        threat_id = "2147951587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "b1e3-3f94e716985f" ascii //weight: 2
        $x_1_2 = "NJRAT.Resources.resource" ascii //weight: 1
        $x_1_3 = "SbkbhXlNVeNC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

