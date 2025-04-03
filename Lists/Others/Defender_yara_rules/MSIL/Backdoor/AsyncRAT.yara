rule Backdoor_MSIL_AsyncRAT_YA_2147735888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.YA!MTB"
        threat_id = "2147735888"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getDrivers" wide //weight: 1
        $x_1_2 = "socketDownload" wide //weight: 1
        $x_1_3 = "sendMemory" wide //weight: 1
        $x_1_4 = "usbSpread" wide //weight: 1
        $x_1_5 = "remoteDesktop" wide //weight: 1
        $x_1_6 = "botKiller" wide //weight: 1
        $x_1_7 = "keyLogger" wide //weight: 1
        $x_1_8 = "uploadFile" wide //weight: 1
        $x_10_9 = ".ddns.ne" wide //weight: 10
        $x_10_10 = "AsyncRAT" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_AsyncRAT_2147755383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT!MTB"
        threat_id = "2147755383"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateProcess\\\\-//" wide //weight: 1
        $x_1_2 = "LoadLibrary\\\\-//" wide //weight: 1
        $x_1_3 = "get_\\\\-//SCII" wide //weight: 1
        $x_1_4 = "Get\\\\-//ppName" wide //weight: 1
        $x_1_5 = "From//-\\\\ase64String" wide //weight: 1
        $x_1_6 = "To//-\\\\ase64String" wide //weight: 1
        $x_1_7 = "//-\\\\reakfastprocurin" wide //weight: 1
        $x_1_8 = "//-\\\\itConverter" wide //weight: 1
        $x_1_9 = "$V//-\\\\$Local_currentProcess" wide //weight: 1
        $x_1_10 = "get_//-\\\\ase\\\\-//ddress" wide //weight: 1
        $x_1_11 = "get_EntryPoint\\\\-//ddress" wide //weight: 1
        $x_1_12 = "Virtual\\\\-//llocEx" wide //weight: 1
        $x_1_13 = "Microsoft SQL Server.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_GG_2147772990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.GG!MTB"
        threat_id = "2147772990"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_1_2 = "Pastebin" ascii //weight: 1
        $x_1_3 = "VIRTUAL" ascii //weight: 1
        $x_1_4 = "vmware" ascii //weight: 1
        $x_1_5 = "SbieDll.dll" ascii //weight: 1
        $x_1_6 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii //weight: 1
        $x_1_7 = "Plugin.Plugin" ascii //weight: 1
        $x_1_8 = "schtasks" ascii //weight: 1
        $x_1_9 = "Packet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_GG_2147772990_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.GG!MTB"
        threat_id = "2147772990"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_1_2 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii //weight: 1
        $x_1_3 = "Plugin.Plugin" ascii //weight: 1
        $x_1_4 = "Pac_ket" ascii //weight: 1
        $x_1_5 = "Log_gers" ascii //weight: 1
        $x_1_6 = "DisableRealtimeMonitoring" ascii //weight: 1
        $x_1_7 = "DisableBehaviorMonitoring" ascii //weight: 1
        $x_1_8 = "llikksat" ascii //weight: 1
        $x_1_9 = "rekcaHssecorP" ascii //weight: 1
        $x_1_10 = "sksathcs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_ZB_2147779168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.ZB!MTB"
        threat_id = "2147779168"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attrib +h +r +s" ascii //weight: 1
        $x_1_2 = "netsh firewall delete allowedprogram" ascii //weight: 1
        $x_1_3 = "SEE_MASK_NOZONECHECKS" ascii //weight: 1
        $x_1_4 = "cmd.exe /c ping 0 -n 2 & del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_ABZ_2147827749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.ABZ!MTB"
        threat_id = "2147827749"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {d2 9c 06 18 02 1e 63 d2 9c 06 17 02 1f 10 63 d2 9c 06 16 02 1f 18 63 d2 9c 06 2a 25 00 1a 8d 1c ?? ?? 01 0a 06 19 02}  //weight: 3, accuracy: Low
        $x_1_2 = "CompressionMode" ascii //weight: 1
        $x_1_3 = "WriteByte" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "RegistryKeyPermissionCheck" ascii //weight: 1
        $x_1_6 = "NetworkStream" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "GetHostAddresses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_ABH_2147827754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.ABH!MTB"
        threat_id = "2147827754"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {57 9f a2 3f 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 77 00 00 00 14 00 00 00 3d 00 00 00 8c 00 00 00 73 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "GetTempFileName" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "UploadValues" ascii //weight: 1
        $x_1_5 = "get_ExecutablePath" ascii //weight: 1
        $x_1_6 = "GetTempPath" ascii //weight: 1
        $x_1_7 = "c schtasks /delete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_ABE_2147829927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.ABE!MTB"
        threat_id = "2147829927"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0c 0f 00 08 20 ?? ?? ?? 00 58 28 01 ?? ?? 2b 07 02 08 20 ?? ?? ?? 00 6f 1a ?? ?? 0a 0d 08 09 58 0c 09 20 ?? ?? ?? 00 2f d8 0f 00 08 28 01 ?? ?? 2b 07 6f 1b ?? ?? 0a de 0a 07 2c 06 07 6f ?? ?? ?? 0a dc}  //weight: 5, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_I_2147835956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.I!MTB"
        threat_id = "2147835956"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 25 0d 2c 05 09 8e 69 2d 05 16 e0 0c 2b 09 09 16 8f 1c 00 00 01 e0 0c 08 28 16 00 00 0a 13 04 11 04 07 8e 69 6a 28 17 00 00 0a 1f 40 12 05 28 01 00 00 06 26 11 04 d0 05 00 00 02 28 18 00 00 0a 28 19 00 00 0a 74 05 00 00 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_J_2147835957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.J!MTB"
        threat_id = "2147835957"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 01 0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {07 20 00 01 00 00 6f ?? 00 00 0a 00 07 20 80 00 00 00 6f ?? 00 00 0a 00 07 17 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 02 7b ?? 00 00 04 6f ?? 00 00 0a 00 02 7b ?? 00 00 04 73 ?? 00 00 0a 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_K_2147835958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.K!MTB"
        threat_id = "2147835958"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 a2 25 17 28 ?? 00 00 0a a2 25 18 28 ?? 00 00 0a a2 25 19 28 ?? 00 00 0a a2 25 1a 28 ?? 00 00 0a 28 ?? 00 00 0a 73 ?? 00 00 0a 28 ?? 00 00 0a 8c ?? 00 00 01 a2 28 ?? 00 00 0a 28 ?? 00 00 06 0a de}  //weight: 2, accuracy: Low
        $x_2_2 = {07 20 80 00 00 00 6f ?? 00 00 0a 07 17 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 07 02}  //weight: 2, accuracy: Low
        $x_1_3 = "CreateSubKey" ascii //weight: 1
        $x_1_4 = "SetValue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_L_2147835959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.L!MTB"
        threat_id = "2147835959"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VirtualAllcEx" ascii //weight: 1
        $x_1_2 = "WriteProcessMem" ascii //weight: 1
        $x_1_3 = "ReadProcessMem" ascii //weight: 1
        $x_1_4 = "ZwUnmapViewOfSec" ascii //weight: 1
        $x_1_5 = "Delegatet____________________________________________________________t" ascii //weight: 1
        $x_1_6 = "Delegatec________________________c" ascii //weight: 1
        $x_1_7 = "RsmThread" ascii //weight: 1
        $x_1_8 = "Execute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_M_2147835960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.M!MTB"
        threat_id = "2147835960"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 28 ?? 00 00 0a 8c ?? 00 00 01 a2 25 17 28 ?? 00 00 0a a2 25 18 28 ?? 00 00 0a a2 25 19 28 ?? 00 00 0a a2 25 1a 28 ?? 00 00 0a 28 ?? 00 00 0a 73 ?? 00 00 0a 28 ?? 00 00 0a 8c ?? 00 00 01 a2 28 ?? 00 00 0a 13 05 73 ?? 00 00 0a 28 ?? 00 00 0a 11 05 6f ?? 00 00 0a 0b 07 6f ?? 00 00 0a 0b 73}  //weight: 2, accuracy: Low
        $x_2_2 = {09 06 91 13 06 08 12 06 20 ?? ?? ?? e9 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 26 06 17 58 0a 06 09 8e 69 32}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_N_2147835961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.N!MTB"
        threat_id = "2147835961"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0c 06 08 7e ?? 00 00 04 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 04 02 0d}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 0a 08 06 6f ?? 00 00 0a 0a 73 ?? 00 00 0a 0d 06 13 06 16 13 05 2b 20 11 06 11 05 91 13 04 09 12 04 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_O_2147835963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.O!MTB"
        threat_id = "2147835963"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 7e ?? ?? 00 04 28 ?? ?? 00 06 a4 ?? 00 00 01 11 ?? 7e ?? ?? 00 04 28 ?? ?? 00 06 7e ?? ?? 00 04 28 ?? ?? 00 06 11 ?? 11 ?? 11 ?? 7e ?? ?? 00 04 28 ?? ?? 00 06 20 00 01 00 00 14 14 11 ?? 7e ?? ?? 00 04 28 ?? ?? 00 06 26 20}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Debugger Detected" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_P_2147835964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.P!MTB"
        threat_id = "2147835964"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 00 06 07 28 ?? ?? ?? 06 7e ?? ?? 00 04 6f ?? 00 00 0a 6f ?? 00 00 0a 20 ?? 00 00 00 28 ?? ?? ?? 06 28 ?? ?? ?? ?? 7e ?? ?? 00 04 28 ?? ?? ?? ?? 6f ?? 00 00 0a 0c dd 17 00 00 00 07 39 07 00 00 00 07 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {08 20 00 01 00 00 ?? ?? ?? ?? ?? 00 08 20 80 00 00 00 6f ?? 00 00 0a 00 08 17 ?? ?? ?? ?? ?? 00 08 18 ?? ?? ?? ?? ?? 00 08 02 7b ?? ?? 00 04 6f ?? 00 00 0a 00 02 7b ?? ?? 00 04 73 ?? 00 00 0a [0-2] 00 [0-2] 07 6f ?? 00 00 0a 1f 20 07}  //weight: 2, accuracy: Low
        $x_1_3 = "X509Certificate2" ascii //weight: 1
        $x_1_4 = "ManagementObjectEnumerator" ascii //weight: 1
        $x_1_5 = "get_UserName" ascii //weight: 1
        $x_1_6 = "get_MachineName" ascii //weight: 1
        $x_1_7 = "get_OSFullName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_Q_2147835965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.Q!MTB"
        threat_id = "2147835965"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 25 2d 17 26 7e ?? ?? 00 04 fe 06 ?? ?? 00 06 73 ?? ?? 00 0a 25 80 ?? ?? 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 72}  //weight: 2, accuracy: Low
        $x_2_2 = {01 07 18 16 8d ?? 00 00 01 28 ?? ?? 00 0a 13 07 11 07 08 18 16}  //weight: 2, accuracy: Low
        $x_1_3 = "GetProcAddress" ascii //weight: 1
        $x_1_4 = "LoadLibrary" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_R_2147835966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.R!MTB"
        threat_id = "2147835966"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 17 58 0a 06 20 00 01 00 00 5d 0a 08 11 06 06 94 58 0c 08 20 00 01 00 00 5d 0c 11 06 06 94 13 04 11 06 06 11 06 08 94 9e 2b 03 0b 2b 87 11 06 08 11 04 9e 2b 06 9e 38 ?? ff ff ff 11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5d 94 0d 2b 06 9e 38 ?? ff ff ff 11 07 07 03 07 91 09 61 d2 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_S_2147835971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.S!MTB"
        threat_id = "2147835971"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 13 04 08 03 17 8d ?? 00 00 01 25 16 1f 5f 9d 6f ?? 01 00 0a 17 9a 03 17 8d ?? 00 00 01 25 16 1f 5f 9d 6f ?? 01 00 0a 17 9a 72 ?? ?? 00 70 28 ?? ?? 00 0a 28 ?? ?? 00 06 6f ?? 00 00 0a 13 05 11 05 16 11 04 16 1f 10 28 ?? 01 00 0a 00 11 05 16 11 04 1f 0f 1f 10 28 ?? 01 00 0a 00 07 11 04 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 13 06 03 28 ?? ?? 00 06 13 07 11 06 11 07 16 11 07 8e 69 6f ?? 00 00 0a 28 ?? 01 00 0a 0d 09 02 16 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_T_2147836962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.T!MTB"
        threat_id = "2147836962"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 03 1e 8d ?? 00 00 01 25 d0 ?? 00 00 04 1b 3a ?? 00 00 00 26 26 73 ?? 00 00 0a 17 3a ?? 00 00 00 26 7e ?? 00 00 04 07 7e ?? 00 00 04 08 1f 20 28 ?? 00 00 06 18 3a ?? 00 00 00 26 26 26 7e ?? 00 00 04 07 7e ?? 00 00 04 08 1f 10 28}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 0d 09 7e ?? 00 00 04 07 28 ?? 00 00 06 17 73 ?? 00 00 0a 13 04 7e ?? 00 00 04 11 04 06 16 06 8e 69 28 ?? 00 00 06 7e ?? 00 00 04 11 04 28 ?? 00 00 06 de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_NRZ_2147840036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.NRZ!MTB"
        threat_id = "2147840036"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 08 28 3d 00 00 0a 7e ?? 00 00 04 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f ?? 00 00 0a 0b de 11}  //weight: 5, accuracy: Low
        $x_1_2 = "cizbckj.Resources" ascii //weight: 1
        $x_1_3 = "XBinder-Output" ascii //weight: 1
        $x_1_4 = "WindowsPrincipal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_NE_2147840037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.NE!MTB"
        threat_id = "2147840037"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 06 08 1e 5a 1e 6f ?? 00 00 0a 18 28 ?? 00 00 0a 9c 08 17 58 0c 08 07 8e 69 17 59 31 e1}  //weight: 5, accuracy: Low
        $x_1_2 = "RayCry5.2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_MK_2147840303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.MK!MTB"
        threat_id = "2147840303"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 1b 58 19 59 17 59 03 8e 69 5d 91 59 20 ?? ?? ?? 00 58 19 59 17 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2d 05 19 2d 39 26 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 19 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_W_2147844624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.W!MTB"
        threat_id = "2147844624"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 2c 15 7e ?? 00 00 04 20 ?? ?? ?? 06 28 ?? 00 00 06 73 ?? 00 00 0a 7a 03 7e ?? 00 00 04 20 50 c3 00 00 73 ?? 00 00 0a 0a 02 06 1f 20 6f ?? 00 00 0a 7d ?? 00 00 04 02 06 1f 40 6f ?? 00 00 0a 7d ?? 00 00 04 de}  //weight: 2, accuracy: Low
        $x_1_2 = "X509Certificate2" ascii //weight: 1
        $x_1_3 = "get_OSFullName" ascii //weight: 1
        $x_1_4 = "get_MachineName" ascii //weight: 1
        $x_1_5 = "get_UserName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_GKH_2147850219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.GKH!MTB"
        threat_id = "2147850219"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 79 00 00 0a 0a 06 28 ?? ?? ?? 0a 03 50 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 7d 00 00 0a 0c 08 07 6f ?? ?? ?? 0a 08 18 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 02 50 16 02 50 8e 69 6f ?? ?? ?? 0a 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_Y_2147900382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.Y!MTB"
        threat_id = "2147900382"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 e8 03 00 00 28 ?? 00 00 06 20 ?? ?? ?? 13 2b ?? 06 17 58 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_ZA_2147901411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.ZA!MTB"
        threat_id = "2147901411"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchost.exe" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "SELECT * FROM __InstanceOperationEvent" ascii //weight: 1
        $x_1_4 = "ActiveProcessCount for killed process" ascii //weight: 1
        $x_1_5 = "cryptercore" wide //weight: 1
        $x_1_6 = "IsDebugEnabled" ascii //weight: 1
        $x_1_7 = "Microsoft.VisualBasic.Devices" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_AB_2147904769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.AB!MTB"
        threat_id = "2147904769"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "XG51Ulxub2lzcmVWdG5lcnJ1Q1xzd29kbmlXXHRmb3NvcmNpTVxlcmF3dGZvUw" wide //weight: 2
        $x_2_2 = "UGFja2V0" wide //weight: 2
        $x_2_3 = "UGluZw" wide //weight: 2
        $x_2_4 = "TWVzc2FnZQ" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_PAEU_2147913350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.PAEU!MTB"
        threat_id = "2147913350"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8e 69 5d 1f 09 58 1f ?? 58 1f ?? 59 91 61 ?? 08 20 0e 02 00 00 58 20 0d 02 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fc 00 00 00 58 1a 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a ?? 8e 69 17 59 6a 06 17 58 6e 5a 31 8f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRAT_PAGL_2147937778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRAT.PAGL!MTB"
        threat_id = "2147937778"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 17 8d 09 00 00 01 13 05 11 05 16 72 01 00 00 70 a2 11 05 0c 07 08 16}  //weight: 2, accuracy: High
        $x_2_2 = "[024578974asf6843sr6g87g67]" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

