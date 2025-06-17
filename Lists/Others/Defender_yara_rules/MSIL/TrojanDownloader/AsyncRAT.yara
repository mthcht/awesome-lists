rule TrojanDownloader_MSIL_AsyncRAT_F_2147819813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.F!MTB"
        threat_id = "2147819813"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://ahmedsyamozo.er.exe" wide //weight: 1
        $x_1_2 = "/explorer.exe" wide //weight: 1
        $x_1_3 = "Concat" ascii //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "Shell" ascii //weight: 1
        $x_1_6 = "AppWinStyle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_K_2147826062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.K!MTB"
        threat_id = "2147826062"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d6 0c 08 11 ?? 13 ?? 11 ?? 31 ?? 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 34 00 7e ?? ?? ?? 04 07 08 16 6f ?? ?? ?? 0a 13 ?? 12 ?? 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 08 17}  //weight: 1, accuracy: Low
        $x_1_2 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_W_2147830128_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.W!MTB"
        threat_id = "2147830128"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 09 28 ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 06 11 04 28 ?? 00 00 0a 13 07 28 ?? 00 00 0a 11 07 6f ?? 00 00 0a 13 08 73 ?? 00 00 0a 06 28}  //weight: 2, accuracy: Low
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "Join" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_N_2147831650_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.N!MTB"
        threat_id = "2147831650"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 ff ff 00 00 0a 02 6f ?? 00 00 0a 0b 16 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {07 08 93 28 ?? 00 00 06 ?? 59 0d 06 09}  //weight: 1, accuracy: Low
        $x_1_3 = {09 06 59 0d 2b}  //weight: 1, accuracy: High
        $x_1_4 = {07 08 09 d1 9d 08 17 58 0c 08 07 8e 69}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 04 20 00 01 00 00 14 14 03 74}  //weight: 1, accuracy: High
        $x_1_6 = "GetType" ascii //weight: 1
        $x_1_7 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_X_2147831651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.X!MTB"
        threat_id = "2147831651"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 01 00 00 38 ?? 00 00 00 38 ?? 00 00 00 20 80 00 00 00 38 ?? 00 00 00 38 ?? 00 00 00 72 ?? 00 00 70 38 ?? 00 00 00 7e ?? 00 00 04 20 e8 03 00 00 73 ?? 00 00 0a 0c 07 08 07 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 07 08 07 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 07 17 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_Z_2147831848_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.Z!MTB"
        threat_id = "2147831848"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 07 09 07 8e 69 5d 91 02 09 91 61 d2 6f ?? 00 00 0a 09 17 58 0d 09 02 8e 69 32}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "get_ASCII" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_Y_2147832621_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.Y!MTB"
        threat_id = "2147832621"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 11 0c 6f ?? 00 00 0a 13 0d ?? [0-1] 72 01 00 00 70 17 8d ?? 00 00 01 13 0e 11 0e 16 11 09 a4 ?? 00 00 01 11 0e 28 ?? 00 00 0a 6f ?? 00 00 0a 72 01 00 00 70 17 8d ?? 00 00 01 13 0f 11 0f 16 11 0d a4 ?? 00 00 01 11 0f 28 ?? 00 00 0a 20 00 01 00 00 14 14 11 0b 74 ?? 00 00 1b 6f ?? 00 00 0a 26 dd}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 13 06 28 ?? 00 00 0a 11 06 6f ?? 00 00 0a 13 07 1f 38 8d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_AB_2147833232_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.AB!MTB"
        threat_id = "2147833232"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 16 1b 6f ?? ?? 00 0a 0b 07 07 6f ?? ?? 00 0a 1c da 1c 6f ?? ?? 00 0a 0b 08 1f 0a da 0c 2b ?? 09 1f 1e 3c}  //weight: 2, accuracy: Low
        $x_1_2 = "GetMethods" wide //weight: 1
        $x_1_3 = "GetExportedTypes" wide //weight: 1
        $x_1_4 = "Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_AF_2147833972_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.AF!MTB"
        threat_id = "2147833972"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set_FileName" ascii //weight: 1
        $x_1_2 = "set_Arguments" ascii //weight: 1
        $x_1_3 = "set_WindowStyle" ascii //weight: 1
        $x_1_4 = "set_CreateNoWindow" ascii //weight: 1
        $x_2_5 = "powershell" wide //weight: 2
        $x_2_6 = "-EncodedCommand" wide //weight: 2
        $x_2_7 = "KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALg" wide //weight: 2
        $x_2_8 = "BEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACc" wide //weight: 2
        $x_2_9 = "LQBDAGgAaQBsAGQAUABhAHQAaAA" wide //weight: 2
        $x_2_10 = "ALQBQAGEAdABoACAAJABlAG4AdgA6AEEAcABwAEQAYQB0AGEA" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_AK_2147833974_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.AK!MTB"
        threat_id = "2147833974"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 13 07 08 07 02 11 07 18 5a 18 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 09 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "ToString" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
        $x_1_4 = "GetResponse" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
        $x_1_6 = "get_UTF8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_AL_2147834223_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.AL!MTB"
        threat_id = "2147834223"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 02 11 07 11 01 02 11 07 18 5a 18 6f ?? 00 00 0a 6f ?? 00 00 0a 9c 38 ?? ff ff ff 11 03 6f ?? 00 00 0a 13 07 38}  //weight: 2, accuracy: Low
        $x_1_2 = "ToString" ascii //weight: 1
        $x_1_3 = "get_UTF8" ascii //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_AO_2147834514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.AO!MTB"
        threat_id = "2147834514"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 72 ?? ?? 00 70 a2 25 17 72 ?? ?? 00 70 a2 25 18 72 ?? ?? 00 70 a2 25 19 72 ?? ?? 00 70 a2 25 1a 72 ?? ?? 00 70 a2 25 1b 72 ?? ?? 00 70 a2 25 1c 72 ?? ?? 00 70 a2 25 1d 72}  //weight: 2, accuracy: Low
        $x_2_2 = {8e 69 17 da 17 d6 8d ?? 00 00 01 13 ?? 11 ?? 8e 69 17 da}  //weight: 2, accuracy: Low
        $x_2_3 = {01 25 16 11 ?? a2 25 13 ?? 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 13 ?? 28 ?? 00 00 0a 11 ?? 16 91 2d 02 2b 0b 11 ?? 16 9a 28 ?? 00 00 0a 13 ?? 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 1f 16 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 16 8c ?? 00 00 01 a2 14 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_AV_2147835157_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.AV!MTB"
        threat_id = "2147835157"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set_FileName" ascii //weight: 1
        $x_1_2 = "set_Arguments" ascii //weight: 1
        $x_1_3 = "set_WindowStyle" ascii //weight: 1
        $x_1_4 = "set_CreateNoWindow" ascii //weight: 1
        $x_2_5 = "powershell" wide //weight: 2
        $x_2_6 = "-EncodedCommand" wide //weight: 2
        $x_2_7 = "CgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGU" wide //weight: 2
        $x_2_8 = "AoAEoAbwBpAG4ALQBQAGEAdABoA" wide //weight: 2
        $x_2_9 = "C0AUABhAHQAaA" wide //weight: 2
        $x_2_10 = "BBAHAAcABEAGEAdABhA" wide //weight: 2
        $x_2_11 = "BTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAALQBGAGkAbABlAFAAYQB0AGg" wide //weight: 2
        $x_2_12 = "AQwBoAGkAbABkAFAAYQB0AGg" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_AX_2147835158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.AX!MTB"
        threat_id = "2147835158"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "-EncodedCommand" wide //weight: 2
        $x_2_3 = "BTAHQAYQByAHQALQBTAGwAZQBlAHAAIAAtAFMAZQBjAG8AbgBkAHM" wide //weight: 2
        $x_2_4 = "E4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlA" wide //weight: 2
        $x_2_5 = "KABKAG8AaQBuAC0AUABhAHQAaA" wide //weight: 2
        $x_2_6 = "AtAFAAYQB0AGgAIAAkAGUAbgB2ADoAQQBwAHAARABhAHQAYQ" wide //weight: 2
        $x_2_7 = "UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoA" wide //weight: 2
        $x_2_8 = "AtAEMAaABpAGwAZABQAGEAdABoA" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_BD_2147835636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.BD!MTB"
        threat_id = "2147835636"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 d6 0d 09 08 31 dc 7e ef 06 00 04 6f ?? 00 00 0a 28 ?? 0d 00 06 26 de}  //weight: 2, accuracy: Low
        $x_1_2 = "EntryPoint" wide //weight: 1
        $x_1_3 = "OpenRead" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_BA_2147836285_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.BA!MTB"
        threat_id = "2147836285"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ijzwkukuizleokktwhkcowa.Fsvfeudripu" wide //weight: 2
        $x_2_2 = "Cuwlvvchq" wide //weight: 2
        $x_2_3 = "edom SOD ni nur eb tonnac margorp sihT!" ascii //weight: 2
        $x_1_4 = "powershell" wide //weight: 1
        $x_2_5 = "Start-Sleep -Seconds 9;Start-Sleep -Seconds 9;" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_BG_2147837510_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.BG!MTB"
        threat_id = "2147837510"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 20 00 0c 00 00 28 ?? 00 00 0a d0 ?? 00 00 1b 28 ?? 00 00 0a 73 ?? 00 00 0a 06 28 ?? 00 00 0a 28 ?? 00 00 0a 72 48 01 00 70 6f ?? 00 00 0a 72 8a 01 00 70 6f ?? 00 00 0a 28 ?? 00 00 0a 74 ?? 00 00 1b 0b 07 72 ae 01 00 70 6f ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "InternetGetConnectedState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_BH_2147837516_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.BH!MTB"
        threat_id = "2147837516"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 a2 14 28 ?? 00 00 0a 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a a2 14 28 ?? 00 00 0a 06 1b 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16 16 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a a2 14 16 17 28}  //weight: 2, accuracy: Low
        $x_1_2 = "GetExportedTypes" wide //weight: 1
        $x_1_3 = "CreateDelegate" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_SP_2147838221_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.SP!MTB"
        threat_id = "2147838221"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {fe 09 07 00 7b 09 00 00 04 6f 0a 00 00 0a fe 09 03 00 71 09 00 00 01 6f 0b 00 00 0a 26 00 fe 09 05 00 71 03 00 00 01 20 01 00 00 00 58 fe 0e 00 00 fe 09 05 00 fe 0c 00 00 81 03 00 00 01 fe 09 05 00 71 03 00 00 01 fe 09 04 00 71 03 00 00 01 fe 02 20 00 00 00 00 fe 01 fe 0e 01 00 fe 09 06 00 fe 0c 01 00 81 14 00 00 01 fe 09 06 00 71 14 00 00 01 3a 0a 00 00 00 20 00 00 00 00 38 06 00 00 00 00 20 01 00 00 00 00 20 fe ff ff ff 5a 20 04 00 00 00 58 fe 0e 02 00 fe 09 00 00 fe 0c 02 00 54 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_BI_2147838563_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.BI!MTB"
        threat_id = "2147838563"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 06 08 06 8e 69 5d 91 7e ?? 00 00 04 08 91 61 d2 6f ?? 00 00 0a 08 17 58 0c}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a 20 00 01 00 00 14 14 14 6f}  //weight: 2, accuracy: High
        $x_1_3 = "GetResponse" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_BM_2147841129_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.BM!MTB"
        threat_id = "2147841129"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "(New-Object Net.WebClient).DownloadString(" wide //weight: 2
        $x_1_3 = "-nop -exec bypass -c" wide //weight: 1
        $x_1_4 = "-WindowStyle hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AsyncRAT_BN_2147841506_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.BN!MTB"
        threat_id = "2147841506"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 04 06 91 20 69 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e}  //weight: 2, accuracy: High
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_BT_2147842197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.BT!MTB"
        threat_id = "2147842197"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8e 69 5d 91 7e ?? 00 00 04 07 91 61 d2 6f ?? 00 00 0a 07 17 58 0b 07 7e ?? 00 00 04 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "GetMethods" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_BW_2147842341_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.BW!MTB"
        threat_id = "2147842341"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {18 5b 11 01 11 04 18 6f ?? 00 00 0a 1f 10 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_CD_2147844269_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.CD!MTB"
        threat_id = "2147844269"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 06 08 91 9c 06 08 09 d2 9c 07 17 58}  //weight: 2, accuracy: High
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_AE_2147844627_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.AE!MTB"
        threat_id = "2147844627"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {04 8e 69 5d 91 02 11 02 91 61 d2 6f}  //weight: 2, accuracy: High
        $x_1_2 = "GetResponse" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
        $x_1_4 = "get_ASCII" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_AP_2147844638_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.AP!MTB"
        threat_id = "2147844638"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 10 00 02 6f ?? 00 00 0a 18 5b 8d ?? 00 00 01 0a 16 0b 2b 18 06 07 02 07 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 07 17 58 0b 07 06 8e 69 32}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 20 00 0f 00 00 60 28 ?? 00 00 0a 72}  //weight: 2, accuracy: Low
        $x_1_3 = "GetString" ascii //weight: 1
        $x_1_4 = "get_ASCII" ascii //weight: 1
        $x_1_5 = "ToCharArray" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
        $x_1_7 = "Download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_BZ_2147845481_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.BZ!MTB"
        threat_id = "2147845481"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 06 02 06 91 03 06 03 8e 69 5d 91 61 d2 9c 06 17 58}  //weight: 2, accuracy: High
        $x_2_2 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_CA_2147846915_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.CA!MTB"
        threat_id = "2147846915"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 0c 29 00 61 52 fe 0c 0d 00 20 01 00 00 00 58 fe 0e ?? 00 fe 0c 26 00 20 01 00 00 00 58 fe}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_AQ_2147847021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.AQ!MTB"
        threat_id = "2147847021"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Izfjfadibvixjlq" wide //weight: 2
        $x_2_2 = "Hmvnikidirtykvb" wide //weight: 2
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_H_2147847168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.H!MTB"
        threat_id = "2147847168"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "QzpcV2luZG93c1xzeXN0ZW0zMlxjbWQuZXhl" wide //weight: 2
        $x_2_2 = "cnVuYXM=" wide //weight: 2
        $x_2_3 = "cG93ZXJzaGVsbC5leGUgQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCBjOlx1c2Vyc1wkZW52OlVTRVJOQU1FXEFwcERhdGFcUm9hbWluZ1w" wide //weight: 2
        $x_2_4 = "HBvd2Vyc2hlbGwuZXhlIEFkZC1NcFByZWZlcmVuY2UgLUV4Y2x1c2lvblBhdGggQzpcVXNlcnNcdmljdGltXEFwcERhdGFcTG9jYWxcVGVtcD" wide //weight: 2
        $x_2_5 = "cG93ZXJzaGVsbC5leGUgQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCBDOlxVc2Vyc1wkZW52OlVTRVJOQU1FXD" wide //weight: 2
        $x_2_6 = "cG93ZXJzaGVsbC5leGUgQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUHJvY2VzcyBDOlxVc2Vyc1x2aWN0aW1cQXBwRGF0YVxMb2NhbFxUZW1wXCo" wide //weight: 2
        $x_2_7 = "C1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVl" wide //weight: 2
        $x_2_8 = "C1EaXNhYmxlU2NyaXB0U2Nhbm5pbmcgJHRydWU" wide //weight: 2
        $x_2_9 = "LURpc2FibGVCZWhhdmlvck1vbml0b3JpbmcgJHRydWU" wide //weight: 2
        $x_2_10 = "LURpc2FibGVJT0FWUHJvdGVjdGlvbiAkdHJ1ZS" wide //weight: 2
        $x_2_11 = "AtRGlzYWJsZUludHJ1c2lvblByZXZlbnRpb25TeXN0ZW0gJHRydWU" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_L_2147847409_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.L!MTB"
        threat_id = "2147847409"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lime_Dropper_" ascii //weight: 2
        $x_2_2 = "DownloadPayload" ascii //weight: 2
        $x_2_3 = "InstallPayload" ascii //weight: 2
        $x_2_4 = "dropPath" ascii //weight: 2
        $x_2_5 = "payloadBuffer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_AH_2147848507_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.AH!MTB"
        threat_id = "2147848507"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BBbH.g.resources" ascii //weight: 2
        $x_2_2 = "/C choice /C Y /N /D Y /T 1 & Del" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_RDL_2147848752_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.RDL!MTB"
        threat_id = "2147848752"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 91 20 54 02 00 00 59 d2 9c 00 06 17 58 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_S_2147849404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.S!MTB"
        threat_id = "2147849404"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 13 07 16 13 09 11 07 12 09 28 ?? 00 00 0a 08 11 06 06 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de}  //weight: 2, accuracy: Low
        $x_2_2 = {06 18 58 0a 06 11 06 6f ?? 00 00 0a fe 04 13 0a 11 0a 2d}  //weight: 2, accuracy: Low
        $x_1_3 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_CE_2147850691_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.CE!MTB"
        threat_id = "2147850691"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0a 02 50 8e 69 17 59 0b 38}  //weight: 2, accuracy: High
        $x_2_2 = {02 50 06 91 0c 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_CG_2147850698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.CG!MTB"
        threat_id = "2147850698"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 ff b6 3f 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 af 02 00 00 cd 02 00 00 4d 08 00 00 1f 31}  //weight: 2, accuracy: High
        $x_2_2 = "PredicateRole" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_SK_2147852033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.SK!MTB"
        threat_id = "2147852033"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0d 11 04 11 06 58 17 58 17 59 11 05 11 07 58 17 58 17 59 6f ?? ?? ?? 0a 13 16 12 16 28 ?? ?? ?? 0a 13 10 11 0c 11 08 11 10 9c 11 08 17 58 13 08 11 07 17 58 13 07 11 07 17 fe 04 13 11 11 11 2d be}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_SL_2147899871_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.SL!MTB"
        threat_id = "2147899871"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 18 d8 0a 06 1f 18 fe 02 0d 09 2c 03 1f 18 0a 00 06 1f 18 5d 16 fe 03 13 04 11 04 2d e2}  //weight: 2, accuracy: High
        $x_2_2 = "nnn.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_BB_2147900696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.BB!MTB"
        threat_id = "2147900696"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "QzpcVXNlcnNc" wide //weight: 2
        $x_2_2 = "XEFwcERhdGFcTG9jYWxcVGVtcFx" wide //weight: 2
        $x_2_3 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" wide //weight: 2
        $x_2_4 = "U3lzdGVtIE1lc3NhZ2U=" wide //weight: 2
        $x_2_5 = "TGVnaXRBcHA" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_SM_2147900852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.SM!MTB"
        threat_id = "2147900852"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 05 11 04 5d 13 08 11 05 1f 16 5d 13 09 11 05 17 58 11 04 5d 13 0a 07 11 08 91 08 11 09 91 61 13 0b 11 0b 07 11 0a 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0c 07 11 08 11 0c d2 9c 11 05 17 58 13 05 00 11 05 11 04 09 17 58 5a fe 04 13 0d 11 0d 2d aa}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_CM_2147904767_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.CM!MTB"
        threat_id = "2147904767"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "param($arguments=\"\")" wide //weight: 2
        $x_2_2 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(" wide //weight: 2
        $x_2_3 = "Invoke-Expression -Command" wide //weight: 2
        $x_2_4 = "mshta vbscript:Execute(" wide //weight: 2
        $x_2_5 = "CreateObject(" wide //weight: 2
        $x_2_6 = ").Run" wide //weight: 2
        $x_2_7 = "powershell -exec Bypass" wide //weight: 2
        $x_2_8 = "Get-ItemProperty" wide //weight: 2
        $x_2_9 = "/create /sc hourly /mo 1 /tn" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_CN_2147908637_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.CN!MTB"
        threat_id = "2147908637"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 20 00 01 00 00 14 fe 09 ?? 00 71 ?? 00 00 01 fe 09 ?? 00 71 ?? 00 00 01 74 ?? 00 00 1b 6f ?? 00 00 0a 26 fe}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_SN_2147914285_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.SN!MTB"
        threat_id = "2147914285"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TournamentTrackerUI.DashBoard.resources" ascii //weight: 2
        $x_2_2 = "$d9cdf6be-9923-4c99-a6bd-ba947b13dba4" ascii //weight: 2
        $x_2_3 = "Reporting Encoding" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_SO_2147931330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.SO!MTB"
        threat_id = "2147931330"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 20 0d 96 01 00 13 05 20 0d 96 01 00 13 06 00 2b 41 00 20 0d 96 01 00 13 07 20 0d 96 01 00 13 08 20 5a e4 01 00 13 09 11 09 20 a3 1c 03 00 fe 01 13 0a 11 0a 2c 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRAT_ELM_2147943878_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRAT.ELM!MTB"
        threat_id = "2147943878"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bookings_056_07.exe" ascii //weight: 1
        $x_2_2 = "Helpfeel Inc" ascii //weight: 2
        $x_1_3 = "Gyazo: Screen Uploader" ascii //weight: 1
        $x_2_4 = "http://144.172.116.121/uiu/Awuolavee.mp3" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

