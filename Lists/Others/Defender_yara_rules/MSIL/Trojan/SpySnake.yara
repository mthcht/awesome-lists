rule Trojan_MSIL_SpySnake_MA_2147794211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MA!MTB"
        threat_id = "2147794211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c5 06 17 58 0a 00 09 17 58 0d 09 20 00 d0 00 00 fe 04 13 06 11 06 2d a8}  //weight: 10, accuracy: High
        $x_1_2 = "firstClicked" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "Timer1_Tick" ascii //weight: 1
        $x_1_5 = "MovementToDown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MA_2147794211_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MA!MTB"
        threat_id = "2147794211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GetBytes" ascii //weight: 1
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetFolderPath" ascii //weight: 1
        $x_1_5 = "Concat" ascii //weight: 1
        $x_1_6 = "GetString" ascii //weight: 1
        $x_10_7 = {0d 09 07 6f ?? ?? ?? 0a 17 1a 00 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 73 28 00 00 0a [0-13] 73 2a 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a de 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MA_2147794211_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MA!MTB"
        threat_id = "2147794211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 15 a2 15 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 81 00 00 00 0b 00 00 00 7a 00 00 00 4b 00 00 00 48 00 00 00 ce}  //weight: 5, accuracy: High
        $x_5_2 = "Game_of_Pig.Properties" ascii //weight: 5
        $x_5_3 = "FIUSHUIF" ascii //weight: 5
        $x_5_4 = "4e7fbb43-d2ae-456a-ad77-4f68aba10107" ascii //weight: 5
        $x_1_5 = "rollButton_Click" ascii //weight: 1
        $x_1_6 = "Enter_Details" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MB_2147794774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MB!MTB"
        threat_id = "2147794774"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 9f a2 29 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 54 00 00 00 1d 00 00 00 3d 00 00 00 b7}  //weight: 5, accuracy: High
        $x_5_2 = "9c550f02-7efa-4ec9-8375-154367b9a606" ascii //weight: 5
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "mwMB3t47odYwVQbETO" ascii //weight: 1
        $x_1_6 = "Stat_Warn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MB_2147794774_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MB!MTB"
        threat_id = "2147794774"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 1d b6 09 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 62 00 00 00 0f 00 00 00 45 00 00 00 68}  //weight: 5, accuracy: High
        $x_5_2 = "74802d9e-635e-4b58-ba09-b5f568ae846e" ascii //weight: 5
        $x_5_3 = "GameInterface.Properties" ascii //weight: 5
        $x_5_4 = "Ex05.GameInterface" ascii //weight: 5
        $x_1_5 = "TicTacToeButton" ascii //weight: 1
        $x_1_6 = "CheckRightLeftDiagonalState" ascii //weight: 1
        $x_1_7 = "OKIJUHYGTF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MB_2147794774_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MB!MTB"
        threat_id = "2147794774"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GetConsoleWindow" ascii //weight: 1
        $x_1_2 = "Sleep" ascii //weight: 1
        $x_1_3 = "WebClient" ascii //weight: 1
        $x_1_4 = {0a 0b 72 01 00 00 70 73 08 00 00 0a 0c 07 08}  //weight: 1, accuracy: High
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2f 00 6d 00 61 00 72 00 69 00 6f 00 6a 00 6f 00 79 00 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_7 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-96] 2f 6d 61 72 69 6f 6a 6f 79 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_8 = "GetType" ascii //weight: 1
        $x_1_9 = "ananakoyz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_MSIL_SpySnake_ME_2147805562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.ME!MTB"
        threat_id = "2147805562"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 06 11 08 9a 1f 10 28 74 00 00 0a 8c 54 00 00 01 6f 75 00 00 0a 26 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d d6}  //weight: 10, accuracy: High
        $x_10_2 = {25 16 11 05 16 9a a2 25 17 11 05 17 9a a2 25 18 72 8f 04 00 70 a2 13 06}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_ME_2147805562_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.ME!MTB"
        threat_id = "2147805562"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 97 a2 3d 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 8d 00 00 00 32 00 00 00 8e}  //weight: 10, accuracy: High
        $x_1_2 = "AppKataCsvViewer.Properties" ascii //weight: 1
        $x_1_3 = "ff868a25-4496-463a-b55e-78de0a45915f" ascii //weight: 1
        $x_1_4 = "ControlCollection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_ME_2147805562_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.ME!MTB"
        threat_id = "2147805562"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/69`1.9`41.09.1`11//:pt`th" wide //weight: 1
        $x_1_2 = "hssssssok" wide //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "duckchoiceselector" ascii //weight: 1
        $x_1_6 = "Gimmeaduck" ascii //weight: 1
        $x_1_7 = "DownloadData" ascii //weight: 1
        $x_1_8 = "username" ascii //weight: 1
        $x_1_9 = "ducknamestouse" ascii //weight: 1
        $x_1_10 = "cookie" wide //weight: 1
        $x_1_11 = "fixedhost.modulation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MF_2147805564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MF!MTB"
        threat_id = "2147805564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 17 a2 0b 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 93 00 00 00 32 00 00 00 ec 01 00 00 82 01 00 00 43 01}  //weight: 10, accuracy: High
        $x_3_2 = "Race_Track.Properties" ascii //weight: 3
        $x_3_3 = "4ffd7815-59a7-4d6e-a811-6f1a27c3ce88" ascii //weight: 3
        $x_3_4 = "Yfeffeeffefea" ascii //weight: 3
        $x_3_5 = "ControlCollection" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MF_2147805564_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MF!MTB"
        threat_id = "2147805564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 38 00 39 00 33 00 31 00 37 00 37 00 33 00 34 00 32 00 34 00 32 00 36 00 35 00 30 00 39 00 33 00 33 00 35 00 2f 00 [0-96] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "NR_DKQODKWQOR" ascii //weight: 1
        $x_1_3 = "NR_D5665" ascii //weight: 1
        $x_1_4 = "NR_Kolasin" ascii //weight: 1
        $x_1_5 = "NR_DetroitSatar" ascii //weight: 1
        $x_1_6 = "SUPER_LOKER" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "get_Value" ascii //weight: 1
        $x_1_10 = "DownloadString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MC_2147808466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MC!MTB"
        threat_id = "2147808466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 09 17 59 11 04 a2 00 09 17 58 0d 09 03 6f ?? ?? ?? 06 fe 02 16 fe 01 13 06 11 06 3a 51 ff ff ff}  //weight: 10, accuracy: Low
        $x_1_2 = "Far0er" ascii //weight: 1
        $x_1_3 = "Sco2e" ascii //weight: 1
        $x_1_4 = "Pa0kage" ascii //weight: 1
        $x_1_5 = "Compla4n.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MC_2147808466_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MC!MTB"
        threat_id = "2147808466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 08 17 58 13 08 20 ?? ?? ?? 9e 38 ?? ?? ?? ff}  //weight: 10, accuracy: Low
        $x_2_2 = "PrisonerManagementSystem_.Properties" ascii //weight: 2
        $x_2_3 = "employeeControl1_Load" ascii //weight: 2
        $x_2_4 = "prisonerControl1_Load" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MC_2147808466_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MC!MTB"
        threat_id = "2147808466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetKonsole" ascii //weight: 1
        $x_1_2 = "Encoder" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "xm4W4bJQaT" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "GetExportedTypes" ascii //weight: 1
        $x_1_7 = "GetTypes" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "get_CurrentDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MD_2147808553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MD!MTB"
        threat_id = "2147808553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 07 11 09 9a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d db}  //weight: 10, accuracy: Low
        $x_10_2 = {25 16 11 06 16 9a a2 25 17 11 06 17 9a a2 25 18 72 ?? ?? ?? 70 a2 13 07 11 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MD_2147808553_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MD!MTB"
        threat_id = "2147808553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 07 8e 69 17 da 0c 2b 13 06 07 08 93 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 08 15 d6 0c 08 16 2f e9}  //weight: 10, accuracy: Low
        $x_1_2 = "ReverseString" ascii //weight: 1
        $x_1_3 = "get_WebBrowser" ascii //weight: 1
        $x_1_4 = "FileDownload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MD_2147808553_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MD!MTB"
        threat_id = "2147808553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0ffa093c-9c0d-4398-bc1b-563986743a5b" ascii //weight: 1
        $x_1_2 = "Ryan Adams" ascii //weight: 1
        $x_1_3 = "JobManagerMonitor" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "get_SnapshotOnShutdown" ascii //weight: 1
        $x_1_7 = "get_SnapshotName" ascii //weight: 1
        $x_1_8 = "lockedVMs" ascii //weight: 1
        $x_1_9 = "get_CloneOnShutdown" ascii //weight: 1
        $x_1_10 = "LockVMCommand" ascii //weight: 1
        $x_1_11 = "WriteToDirRename" ascii //weight: 1
        $x_1_12 = "get_Key" ascii //weight: 1
        $x_1_13 = "GetString" ascii //weight: 1
        $x_1_14 = "CreateInstance" ascii //weight: 1
        $x_1_15 = "get_MachineName" ascii //weight: 1
        $x_1_16 = "add_KeyUp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MG_2147808838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MG!MTB"
        threat_id = "2147808838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 09 07 09 9a 1f 10 28 ?? ?? ?? 0a 9c 09 17 d6 0d 00 09 07 8e 69 fe 04 13 05 11 05 2d e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MG_2147808838_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MG!MTB"
        threat_id = "2147808838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 15 a2 09 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 6d 00 00 00 19 00 00 00 b4 00 00 00 bd}  //weight: 10, accuracy: High
        $x_10_2 = "75912347-b27c-4ac1-8756-1daeff304d8" ascii //weight: 10
        $x_1_3 = "eatSomething" ascii //weight: 1
        $x_1_4 = "B0203204" ascii //weight: 1
        $x_1_5 = "D52847352345" ascii //weight: 1
        $x_1_6 = "Evolution_Simulation.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MG_2147808838_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MG!MTB"
        threat_id = "2147808838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TEMP\\nsd28BD.tmp\\wffg.dll" ascii //weight: 1
        $x_1_2 = "vanquishing\\bitsy.exe" ascii //weight: 1
        $x_1_3 = "disgust\\ironing.bat" ascii //weight: 1
        $x_1_4 = "admonish\\glittering.bat" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\portions\\marmalade" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\intimacy" ascii //weight: 1
        $x_1_7 = "Sleep" ascii //weight: 1
        $x_1_8 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MH_2147809309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MH!MTB"
        threat_id = "2147809309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 09 07 11 09 9a 1f 10 28 ?? ?? ?? 0a 9c 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MH_2147809309_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MH!MTB"
        threat_id = "2147809309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 18 5b 8d 31 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 08 18 58 0c 08 06 32 e4}  //weight: 5, accuracy: Low
        $x_5_2 = "://185.216.71.120/" wide //weight: 5
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "Rooll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MH_2147809309_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MH!MTB"
        threat_id = "2147809309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GetTypes" ascii //weight: 1
        $x_1_2 = "DebuggableAttribute" ascii //weight: 1
        $x_1_3 = "DTT.exe" ascii //weight: 1
        $x_1_4 = "GameWindow" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "OthelloWindowsApplication" ascii //weight: 1
        $x_1_7 = {19 8d 0a 00 00 01 25 16 72 17 00 00 70 a2 25 17 72 5d 00 00 70 a2 25 18 07 06 28 ?? ?? ?? 06 a2 0c 20 05 00 00 00 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MJ_2147811765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MJ!MTB"
        threat_id = "2147811765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5d 94 13 07 09 11 05 08 11 05 91 11 07 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 95}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MJ_2147811765_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MJ!MTB"
        threat_id = "2147811765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 00 06 72 c8 03 00 70 7d 27 00 00 04 28 ?? ?? ?? 06 06 fe 06 30 00 00 06 73 1b 00 00 0a 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0b 07 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 0c 12 02 28 ?? ?? ?? 0a 00 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "$PASSWORD$" wide //weight: 1
        $x_1_3 = "GetLogger" ascii //weight: 1
        $x_1_4 = "Sc3een" ascii //weight: 1
        $x_1_5 = "ThreadStart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MJ_2147811765_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MJ!MTB"
        threat_id = "2147811765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 16 d0 ?? 00 00 01 28 ?? ?? ?? 0a 35 00 d0 12 00 00 01 28 ?? ?? ?? 0a 72 ?? 00 00 70 72 ?? 00 00 70 72 ?? 00 00 70 28 ?? ?? ?? ?? 17 8d [0-18] a2 28 ?? ?? ?? 0a 73 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 72 ?? 00 00 70 a2 6f ?? ?? ?? 0a 74 ?? 00 00 1b}  //weight: 1, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MK_2147811768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MK!MTB"
        threat_id = "2147811768"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 06 06 11 06 9a 1f 10 28 ?? ?? ?? 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de}  //weight: 5, accuracy: Low
        $x_1_2 = "AnalyzeControl" ascii //weight: 1
        $x_1_3 = "NetToSwing.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MK_2147811768_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MK!MTB"
        threat_id = "2147811768"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {57 97 a2 29 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 b3 00 00 00 52 00 00 00 96 01}  //weight: 3, accuracy: High
        $x_3_2 = "33da840a-7133-4f5a-9749-c0b5b5928867" ascii //weight: 3
        $x_3_3 = "Mahjong.Properties" ascii //weight: 3
        $x_3_4 = "Debug_InformationKey" ascii //weight: 3
        $x_3_5 = "TcpListener" ascii //weight: 3
        $x_3_6 = "SocketException" ascii //weight: 3
        $x_3_7 = "King_Black" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MK_2147811768_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MK!MTB"
        threat_id = "2147811768"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mddpmkIfkk" ascii //weight: 1
        $x_1_2 = "chrom\\chrom.exe" wide //weight: 1
        $x_1_3 = "ENCLogTable" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "DynamicDllInvokeType" wide //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "#fdgdfadgd.dll#" ascii //weight: 1
        $x_1_8 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateDecryptor" ascii //weight: 1
        $x_1_11 = "Encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_ML_2147811769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.ML!MTB"
        threat_id = "2147811769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 16 0c 2b 19 07 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 18 58 0c 08 06 32 e3}  //weight: 5, accuracy: Low
        $x_5_2 = {57 15 02 08 09 0b 00 00 00 5a a4 00 00 16 00 00 01 00 00 00 31}  //weight: 5, accuracy: High
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "eaab72bc-a594-49bd-971a-696bdce93b9f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_ML_2147811769_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.ML!MTB"
        threat_id = "2147811769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#sadadfgds.dll#" ascii //weight: 1
        $x_1_2 = "chrom\\chrom.exe" wide //weight: 1
        $x_1_3 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_4 = "IsLogging" ascii //weight: 1
        $x_1_5 = "ObfuscatedByGoliath" ascii //weight: 1
        $x_1_6 = "FlushFinalBlock" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_ML_2147811769_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.ML!MTB"
        threat_id = "2147811769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 5d a2 c9 09 01 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 5d 00 00 00 0b 00 00 00 32 00 00 00 de 00 00 00 2e 00 00 00 92}  //weight: 5, accuracy: High
        $x_2_2 = "561e7a93-d222-4cbd-abc0-59c70e8b74ed" ascii //weight: 2
        $x_2_3 = "_2048WindowsFormsApp.Properties" wide //weight: 2
        $x_2_4 = "RulesOfTheGameForm" wide //weight: 2
        $x_2_5 = "CASCX" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MO_2147812289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MO!MTB"
        threat_id = "2147812289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 9f b6 2b 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 83 00 00 00 36 00 00 00 69 00 00 00 4c 01 00 00 1b 01 00 00 0e}  //weight: 10, accuracy: High
        $x_5_2 = "VirtualMemSim.Properties" ascii //weight: 5
        $x_1_3 = "LazyList" ascii //weight: 1
        $x_1_4 = "get_ProcessID" ascii //weight: 1
        $x_1_5 = "connectionId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MO_2147812289_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MO!MTB"
        threat_id = "2147812289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SoftKinsoku" ascii //weight: 1
        $x_1_2 = "b8b35427-7b2b-41e9-8a5b-5507e3870c12" ascii //weight: 1
        $x_1_3 = "Calzone" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
        $x_1_7 = "DeleteExtractionFolder" ascii //weight: 1
        $x_1_8 = "Hiddenreserved" ascii //weight: 1
        $x_1_9 = "MissingLockState" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "Uppercase" ascii //weight: 1
        $x_1_12 = "Debug" ascii //weight: 1
        $x_1_13 = "get_Hidden" ascii //weight: 1
        $x_1_14 = "UpperLeft" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MQ_2147813151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MQ!MTB"
        threat_id = "2147813151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 3f b6 1d 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9b 00 00 00 13 00 00 00 7c 00 00 00 90 00 00 00 9a}  //weight: 10, accuracy: High
        $x_5_2 = "1c7c6a4e-b16a-4ed4-8813-5aa30e9efc69" ascii //weight: 5
        $x_1_3 = "Jambo" ascii //weight: 1
        $x_1_4 = "webBrowser_NavigateComplete" ascii //weight: 1
        $x_1_5 = "PassUrlToBroker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MQ_2147813151_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MQ!MTB"
        threat_id = "2147813151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 62 d1 43 42 32 68 69 68 64 68 6f 90 9b 18 38 f9 43 41 32 68 69 6c 64 28 6f 6f 64 18 38 41 43 41 32 68 69}  //weight: 5, accuracy: High
        $x_5_2 = {d0 98 d0 b8 d1 81 d1 83 d1 81 50 37 72 63 37 6e 74 61 67 37 2e 50 72 6f 70 65 72 74 69 65 73}  //weight: 5, accuracy: High
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "get_Access_token" ascii //weight: 1
        $x_1_5 = "ExceptionLogger" ascii //weight: 1
        $x_1_6 = "get_DataDiskImages" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MQ_2147813151_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MQ!MTB"
        threat_id = "2147813151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OIUTERSWBAJHGFF" ascii //weight: 1
        $x_1_2 = "PLOKNMJIUHBVGYTFC" ascii //weight: 1
        $x_1_3 = "MDIPP1Z" ascii //weight: 1
        $x_1_4 = "numericUpDown1_ValueChanged" ascii //weight: 1
        $x_1_5 = "MDIPP1" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "DealDamage" ascii //weight: 1
        $x_1_8 = "NumericUpDown" ascii //weight: 1
        $x_1_9 = "get_KillCount" ascii //weight: 1
        $x_1_10 = "9c54b190-e5ca-4b42-8fbc-2e0f8a163fcc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MR_2147813790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MR!MTB"
        threat_id = "2147813790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 16 07 06 9a a2 25 17 1f 10 8c 4a 00 00 01 a2 6f ?? ?? ?? 0a a5 06 00 00 01 9c 06 17 58 0a 06 07 8e 69 fe 04 13 08 11 08 2d ad}  //weight: 10, accuracy: Low
        $x_5_2 = "c89ec013-14fd-4281-aa3b-dd4605d3275f" ascii //weight: 5
        $x_1_3 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MR_2147813790_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MR!MTB"
        threat_id = "2147813790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 00 2b 1f 09 20 e5 8e fb 0e fe 01 13 1a 11 1a 2c 09 20 1c 8f fb 0e 0d 00 2b 08 00 20 01 8f fb 0e 0d 00}  //weight: 10, accuracy: High
        $x_2_2 = {50 45 00 00 4c 01 03 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 e0 00 02 01 0b 01 50}  //weight: 2, accuracy: Low
        $x_2_3 = "StrReverse" ascii //weight: 2
        $x_2_4 = "Create__Instance__" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MR_2147813790_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MR!MTB"
        threat_id = "2147813790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 07 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 7e ?? 00 00 04 06 6f ?? ?? ?? 0a 00 7e ?? 00 00 04 18 6f ?? ?? ?? 0a 00 7e ?? 00 00 04 6f ?? ?? ?? 0a 80 ?? 00 00 04 02 28 ?? ?? ?? 06 0c 08 0d 7e ?? 00 00 04 6f ?? ?? ?? 0a 00 09 13 04 2b 00 11 04 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "HashPasswordForStoringInConfigFile" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "Calzone" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_1_7 = "TransformFinalBlock" ascii //weight: 1
        $x_1_8 = "GetDomain" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_2147813795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MT!MTB"
        threat_id = "2147813795"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 16 0d 2b 16 06 09 28 ?? ?? ?? 06 13 04 07 09 11 04 6f ?? ?? ?? 0a 09 18 58 0d 09 06 6f ?? ?? ?? 0a 32 e1}  //weight: 10, accuracy: Low
        $x_1_2 = "GetDomain" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_2147813795_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MT!MTB"
        threat_id = "2147813795"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 11 08 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de}  //weight: 10, accuracy: Low
        $x_1_2 = "GameForm_KeyDown" ascii //weight: 1
        $x_1_3 = "e07cda72-71b3-4295-8657-d7aa1b3b5b13" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_2147813795_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MT!MTB"
        threat_id = "2147813795"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 04 9a 13 05 11 05 6f ?? ?? ?? 0a 72 ?? 00 00 70 28 ?? ?? ?? 0a 13 06 11 06 2c 4d 00 11 05 6f ?? ?? ?? 0a 13 07 16 13 08 2b 36 11 07 11 08 9a 13 09 11 09 6f ?? ?? ?? 0a 72 ?? 01 00 70 28 ?? ?? ?? 0a 13 0a 11 0a 2c 12 11 09 14 14 6f ?? ?? ?? 0a a5 ?? 00 00 01 13 0b 2b 2d 11 08 17 58 13 08 11 08 11 07 8e 69 32 c2}  //weight: 1, accuracy: Low
        $x_1_2 = "CurrentDomain" wide //weight: 1
        $x_1_3 = "QueueUserWorkItem" ascii //weight: 1
        $x_1_4 = "/c ping bing.com" wide //weight: 1
        $x_1_5 = "FromSeconds" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
        $x_1_7 = "Reverse" wide //weight: 1
        $x_1_8 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MV_2147814214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MV!MTB"
        threat_id = "2147814214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 02 8e 69 18 5a 06 8e 69 58 0b 2b 3b 02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61}  //weight: 10, accuracy: High
        $x_5_2 = {57 17 a2 0b 09 07 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 68 00 00 00 21 00 00 00 45 00 00 00 74}  //weight: 5, accuracy: High
        $x_5_3 = "Game_winform.Properties" ascii //weight: 5
        $x_2_4 = "ControlCollection" ascii //weight: 2
        $x_2_5 = "GetExportedTypes" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MV_2147814214_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MV!MTB"
        threat_id = "2147814214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "NLXhHWXASGIQiZn.RYyRqpQcgSVGrjV" wide //weight: 5
        $x_5_2 = "hcIKymXVZAWimeN" wide //weight: 5
        $x_2_3 = {13 0d 11 0d 72 f7 03 0c 70 28 ?? ?? ?? 0a 13 0d 11 0d 72 e7 03 0c 70 28 ?? ?? ?? 0a 13 0d 11 0d 72 cb 04 0c 70 28 ?? ?? ?? 0a 13 0d 11 0d 72 ff 03 0c 70 28 ?? ?? ?? 0a 13 0d 11 0d 72 cb 04 0c 70 28 ?? ?? ?? 0a 13 0d 11 0d 72 cf 04 0c 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MV_2147814214_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MV!MTB"
        threat_id = "2147814214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 07 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 7e ?? 00 00 04 06 6f ?? ?? ?? 0a 00 7e ?? 00 00 04 18 6f ?? ?? ?? 0a 00 7e ?? 00 00 04 6f ?? ?? ?? 0a 80 ?? 00 00 04 02 28 ?? ?? ?? 06 0c 08 0d 7e ?? 00 00 04 6f ?? ?? ?? 0a 00 09 13 04 2b 00 11 04 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "GetDomain" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "Kingston" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MW_2147814893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MW!MTB"
        threat_id = "2147814893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 ?? ?? ?? ?? ?? 6e 02 07 17 58 02 8e 69 5d 91}  //weight: 10, accuracy: Low
        $x_5_2 = "getStake" ascii //weight: 5
        $x_5_3 = "PromoCore.Properties" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MW_2147814893_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MW!MTB"
        threat_id = "2147814893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "NLXhHWXASGIQiZn.RYyRqpQcgSVGrjV" wide //weight: 5
        $x_5_2 = "hcIKymXVZAWimeN" wide //weight: 5
        $x_2_3 = {13 0e 11 0e 72 d5 04 0c 70 28 ?? ?? ?? 0a 13 0e 11 0e 72 c5 04 0c 70 28 ?? ?? ?? 0a 13 0e 11 0e 72 2d 05 0c 70 28 ?? ?? ?? 0a 13 0e 11 0e 72 dd 04 0c 70 28 ?? ?? ?? 0a 13 0e 11 0e 72 2d 05 0c 70 28 ?? ?? ?? 0a 13 0e 11 0e 72 31 05 0c 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MW_2147814893_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MW!MTB"
        threat_id = "2147814893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 07 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 7e ?? 00 00 04 06 6f ?? ?? ?? 0a 00 7e ?? 00 00 04 18 6f ?? ?? ?? 0a 00 7e ?? 00 00 04 6f ?? ?? ?? 0a 80 ?? 00 00 04 02 28 ?? ?? ?? 06 0c 08 0d 7e ?? 00 00 04 6f ?? ?? ?? 0a 00 09 13 04 2b 00 11 04 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Mirarmar" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "GetDomain" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MZ_2147814896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MZ!MTB"
        threat_id = "2147814896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 02 16 02 8e 69 6f 77 00 00 0a 0c 08 0d de 0b 07 2c 07 07 6f ?? ?? ?? 0a 00 dc 09 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "D6ngerous" ascii //weight: 1
        $x_1_3 = "Adjustm4nt" ascii //weight: 1
        $x_1_4 = "Som5tim5s" ascii //weight: 1
        $x_1_5 = "Growi1g" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MZ_2147814896_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MZ!MTB"
        threat_id = "2147814896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 17 b6 09 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 6a 00 00 00 37 00 00 00 08 01}  //weight: 10, accuracy: High
        $x_5_2 = "160047c3-2c20-44e0-9aaf-9f072ed2b333" ascii //weight: 5
        $x_5_3 = "Jambo" ascii //weight: 5
        $x_5_4 = "BLL_DAL.Properties" ascii //weight: 5
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "TransformFinalBlock" ascii //weight: 1
        $x_1_8 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MZ_2147814896_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MZ!MTB"
        threat_id = "2147814896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 0c 2b 00 08 2a 3f 00 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 7e ?? ?? ?? 04 06 6f ?? ?? ?? 0a 00 7e ?? ?? ?? 04 18 6f ?? ?? ?? 0a 00 02 28 ?? ?? ?? 06}  //weight: 1, accuracy: Low
        $x_1_2 = "Mirarmar" ascii //weight: 1
        $x_1_3 = "GetHostEntry" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "RetrieveData" ascii //weight: 1
        $x_1_7 = "TransformFinalBlock" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAA_2147814897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAA!MTB"
        threat_id = "2147814897"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 0c 2b 00 08 2a 3f 00 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 7e ?? ?? ?? 04 06 6f ?? ?? ?? 0a 00 7e ?? ?? ?? 04 18 6f ?? ?? ?? 0a 00 02 28 ?? ?? ?? 06}  //weight: 1, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "ShowPassword_MouseDown" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "txtPassword_TextChanged" ascii //weight: 1
        $x_1_7 = "txtName_KeyPress" ascii //weight: 1
        $x_1_8 = "CreditCard_CheckedChanged" ascii //weight: 1
        $x_1_9 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAB_2147814898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAB!MTB"
        threat_id = "2147814898"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Reverse" ascii //weight: 1
        $x_1_2 = "Kzuexulwhlfuxepd" wide //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "Enqueue" ascii //weight: 1
        $x_1_5 = "Dequeue" ascii //weight: 1
        $x_1_6 = "sworhTnoitpecxEnoNparW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAC_2147815336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAC!MTB"
        threat_id = "2147815336"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Enqueue" ascii //weight: 1
        $x_1_2 = "Dequeue" ascii //weight: 1
        $x_1_3 = "Rsjhrkbgtlqluaobtoqahir" wide //weight: 1
        $x_1_4 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 39 00 [0-96] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_5 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAD_2147815337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAD!MTB"
        threat_id = "2147815337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 0c 2b 00 08 2a 3f 00 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 7e ?? ?? ?? 04 06 6f ?? ?? ?? 0a 00 7e ?? ?? ?? 04 18 6f ?? ?? ?? 0a 00 02 28 ?? ?? ?? 06}  //weight: 1, accuracy: Low
        $x_1_2 = "Mirarmar" ascii //weight: 1
        $x_1_3 = "DownloadQueue" ascii //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "UrlDecode" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
        $x_1_9 = "TransformFinalBlock" ascii //weight: 1
        $x_1_10 = "Proxy-Connection" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAF_2147815733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAF!MTB"
        threat_id = "2147815733"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 0c 2b 00 08 2a 3f 00 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 7e ?? ?? ?? 04 06 6f ?? ?? ?? 0a 00 7e ?? ?? ?? 04 18 6f ?? ?? ?? 0a 00 02 28 ?? ?? ?? 06}  //weight: 1, accuracy: Low
        $x_1_2 = "Mirarmar" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAG_2147819716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAG!MTB"
        threat_id = "2147819716"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1d 2d 0b 2b 41 02 8e 69 1c 2d 06 26 2b 0d 0a 2b f4 0b 2b f8 06 07 02 07 91 2b 0e 07 25 17 59 17 2d 13 26 16 fe 02 0c 2b 07 6f ?? ?? ?? 0a 2b eb 08 2d e1 2b 03 0b 2b eb}  //weight: 1, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "Yknbhpsjkxiqrzvyzaovb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAK_2147823660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAK!MTB"
        threat_id = "2147823660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 2b 03 00 2b 07 6f ?? ?? ?? 0a 2b f6 07 6f ?? ?? ?? 0a 0c de 11 07 2b 08 07 6f ?? ?? ?? 0a 2b 04 2c 03 2b f4 00 dc 08 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "DebuggableAttribute" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 39 00 38 00 31 00 31 00 30 00 36 00 30 00 38 00 33 00 34 00 35 00 34 00 31 00 32 00 34 00 30 00 37 00 35 00 [0-128] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_7 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAL_2147823662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAL!MTB"
        threat_id = "2147823662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 16 07 8e 69 28 ?? ?? ?? 0a 00 07 0c 2b 00 08 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "DynamicInvoke" ascii //weight: 1
        $x_1_3 = {3a 00 2f 00 2f 00 6d 00 69 00 63 00 6b 00 65 00 79 00 35 00 31 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 6f 00 72 00 64 00 70 00 72 00 65 00 73 00 73 00 2f 00 77 00 70 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2f 00 6d 00 65 00 64 00 69 00 61 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 [0-96] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAJ_2147825197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAJ!MTB"
        threat_id = "2147825197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TG5jZ2F3Q39rbHp/ZWJgNTA=" wide //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "ActionBlock" ascii //weight: 1
        $x_1_4 = "OnDisabled" ascii //weight: 1
        $x_1_5 = "IRemoteTestDiscoveryService" ascii //weight: 1
        $x_1_6 = "SetStateMachine" ascii //weight: 1
        $x_1_7 = "get_Log_Bulk_Analysis_Solution_Snapshot_Missing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAM_2147825200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAM!MTB"
        threat_id = "2147825200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 16 6f 43 00 00 0a 00 72 2d 00 00 70 28 44 00 00 0a 26 28 45 00 00 0a 00 2a 30 00 28 06 00 00 06 6f 42 00 00 0a 72 2d 00 00 70}  //weight: 1, accuracy: Low
        $x_1_2 = "Windows\\Temp\\Software.vbs" wide //weight: 1
        $x_1_3 = "WriteAllBytes" ascii //weight: 1
        $x_1_4 = "Create__Instance" ascii //weight: 1
        $x_1_5 = "get_vbs" ascii //weight: 1
        $x_1_6 = "set_ShutdownStyle" ascii //weight: 1
        $x_1_7 = "CheckForSyncLockOnValueType" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_ABK_2147827755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.ABK!MTB"
        threat_id = "2147827755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 11 04 16 09 16 1f 10 28 ?? ?? ?? 0a 11 04 16 09 1f 0f 1f 10 28 ?? ?? ?? 0a 06 09 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 13 05 02 28 ?? ?? ?? 0a 13 06 28 ?? ?? ?? 0a 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c de 03}  //weight: 10, accuracy: Low
        $x_1_2 = "IAsyncLocal" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAN_2147827762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAN!MTB"
        threat_id = "2147827762"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 11 04 16 09 16 1f 10 28 ?? ?? ?? 0a 11 04 16 09 1f 0f 1f 10 28 ?? ?? ?? 0a 06 09 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 13 05 02 28 ?? ?? ?? 0a 13 06 28 ?? ?? ?? 0a 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c de 03}  //weight: 10, accuracy: Low
        $x_1_2 = "IAsyncLocal" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
        $x_1_7 = "DownloadData" ascii //weight: 1
        $x_1_8 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAO_2147827763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAO!MTB"
        threat_id = "2147827763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 94 a2 29 09 0f 00 00 00 fa 25 33 00 16}  //weight: 1, accuracy: High
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "HideModuleNameAttribute" ascii //weight: 1
        $x_1_5 = "get_ExecutablePath" ascii //weight: 1
        $x_1_6 = "InvokeMember" ascii //weight: 1
        $x_1_7 = "Select * From PatientTb" wide //weight: 1
        $x_1_8 = "aaMaeatahaoada0a" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAQ_2147828809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAQ!MTB"
        threat_id = "2147828809"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 16 09 1f 0f 1f 10 28 ?? ?? ?? 0a 06 09 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 13 05 02 28 ?? ?? ?? 0a 13 06 28 ?? ?? ?? 0a 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c dd 06 00 00 00 26 dd 00 00 00 00 08 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "HandleIncomingConnections" ascii //weight: 1
        $x_1_3 = "shutdown the server" wide //weight: 1
        $x_1_4 = "IAsyncLocal" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAR_2147829200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAR!MTB"
        threat_id = "2147829200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "055b92b5-afc3-4625-a33f-26efc69d09b7" ascii //weight: 1
        $x_1_2 = "Shitz" ascii //weight: 1
        $x_1_3 = "VlakRegion.Model.Properties.Resources" ascii //weight: 1
        $x_1_4 = "Jambo" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAS_2147830106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAS!MTB"
        threat_id = "2147830106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 9f b6 2b 09 1e 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 5c 01 00 00 95 01 00 00 ed 05}  //weight: 1, accuracy: High
        $x_1_2 = "DynamicInvoke" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "currentPosition" ascii //weight: 1
        $x_1_6 = "fullyTrusted" ascii //weight: 1
        $x_1_7 = "CodeAccessPermission" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAT_2147830107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAT!MTB"
        threat_id = "2147830107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 df b6 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 1d 01 00 00 a3 00 00 00 a5}  //weight: 1, accuracy: High
        $x_1_2 = "HideConsole" ascii //weight: 1
        $x_1_3 = "ConsoleKeyInfo" ascii //weight: 1
        $x_1_4 = "treePostWindowMouseAt" ascii //weight: 1
        $x_1_5 = "treePostWindow_KeyUp" ascii //weight: 1
        $x_1_6 = "ReleaseCapture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAU_2147830388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAU!MTB"
        threat_id = "2147830388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 55 b6 df 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 c1 00 00 00 21 00 00 00 ea 00 00 00 17 07 00 00 f7}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "FormStartPosition" ascii //weight: 1
        $x_1_4 = "MailMessage" ascii //weight: 1
        $x_1_5 = "NetworkCredential" ascii //weight: 1
        $x_1_6 = "add_MouseDown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAV_2147830391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAV!MTB"
        threat_id = "2147830391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 16 06 8e 69 6f ?? ?? ?? 0a 0d 09 8e 69 1f 10 59 8d ?? ?? ?? 01 13 04 09 1f 10 11 04 16 09 8e 69 1f 10 59 28 ?? ?? ?? 0a 11 04 03 6b 28 ?? ?? ?? 06 28 ?? ?? ?? 06 ?? ?? ?? ?? ?? 28 ?? ?? ?? 06 6f ?? ?? ?? 0a ?? ?? ?? ?? ?? 03 02 ?? ?? ?? ?? ?? 13 05 11 05 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "SnakeI.Properties" ascii //weight: 1
        $x_1_3 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_4 = "SetWindowPos" ascii //weight: 1
        $x_1_5 = "get_KeyCode" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAX_2147830928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAX!MTB"
        threat_id = "2147830928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 15 a2 09 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 44 00 00 00 06 00 00 00 2d}  //weight: 10, accuracy: High
        $x_1_2 = "Jambo" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_1_7 = "SoldireData.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MP_2147834235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MP!MTB"
        threat_id = "2147834235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 11 06 06 11 06 9a 1f 10 28 ?? ?? ?? 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de}  //weight: 10, accuracy: Low
        $x_5_2 = "SaluteForm_MouseDown" ascii //weight: 5
        $x_5_3 = "StringFormatEx.Properties" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MP_2147834235_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MP!MTB"
        threat_id = "2147834235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 07 06 28 ?? ?? ?? 06 d2 6f ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c0}  //weight: 10, accuracy: Low
        $x_1_2 = "10777fd4-c40a-4d3e-9ce6-bd8e8139e254" ascii //weight: 1
        $x_1_3 = "CheatMenu.Properties" ascii //weight: 1
        $x_1_4 = "Alor_22" ascii //weight: 1
        $x_1_5 = "Alor_28" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MS_2147834296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MS!MTB"
        threat_id = "2147834296"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 1f a2 0b 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 72 00 00 00 6c 00 00 00 10 01 00 00 2c 02 00 00 82 01 00 00 02 00 00 00 86}  //weight: 10, accuracy: High
        $x_5_2 = "YuChang.Core.Properties" ascii //weight: 5
        $x_1_3 = "QR_SCENE" ascii //weight: 1
        $x_1_4 = "postData" ascii //weight: 1
        $x_1_5 = "get_NextOpenId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MS_2147834296_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MS!MTB"
        threat_id = "2147834296"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {17 13 1e 20 e6 8e fb 0e 13 1f 11 1f 20 ed 8e fb 0e fe 02 13 5e 11 5e 2c 09 20 f8 8e fb 0e 13 1f 2b 1d 11 1f 20 1e 8f fb 0e fe 02 16 fe 01 13 5f 11 5f 2c 08}  //weight: 10, accuracy: High
        $x_10_2 = {57 95 a2 29 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 74 00 00 00 16 00 00 00 51 00 00 00 ?? 01 00 00 ?? 00 00 00 cd 00 00 00 28 00 00 00 07 00 00 00 ?? 00 00 00 04 00 00 00 09 00 00 00 10 00 00 00 04}  //weight: 10, accuracy: Low
        $x_10_3 = "4281b208-39a5-4cc4-b524-6e9af626f621" ascii //weight: 10
        $x_10_4 = "Malaga_game.Properties" ascii //weight: 10
        $x_5_5 = "Self installation" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SpySnake_MU_2147834378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MU!MTB"
        threat_id = "2147834378"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 02 8e 69 18 5a 06 8e 69 58 0b 2b 3d 00 02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61}  //weight: 10, accuracy: High
        $x_5_2 = "Klient do blipa" ascii //weight: 5
        $x_5_3 = "BlipFace.Properties" ascii //weight: 5
        $x_1_4 = "hotkey_HotkeyPressed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MU_2147834378_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MU!MTB"
        threat_id = "2147834378"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 15 a2 09 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 99 00 00 00 11 00 00 00 98 00 00 00 81 00 00 00 ab 00 00 00 6b 01 00 00 18}  //weight: 10, accuracy: High
        $x_5_2 = "Jambo" ascii //weight: 5
        $x_5_3 = "c121b5f5-32bc-4e2d-9b8c-aad71ed74d7f" ascii //weight: 5
        $x_5_4 = "StockPlot.Properties" ascii //weight: 5
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MU_2147834378_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MU!MTB"
        threat_id = "2147834378"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Reverse" ascii //weight: 1
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_4 = "DelapedLoop" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
        $x_1_6 = "Hidden Reflex Authors" wide //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "Nrjlsk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MY_2147835234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MY!MTB"
        threat_id = "2147835234"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 06 06 11 06 9a 1f 10 28 ?? ?? ?? 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de}  //weight: 2, accuracy: Low
        $x_1_2 = "WFA_Yacht_Dice.Properties" ascii //weight: 1
        $x_1_3 = "ce9831ff-3d85-42ae-9e38-ad384ec31955" ascii //weight: 1
        $x_1_4 = "timer_receiveOnly_Tick" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MY_2147835234_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MY!MTB"
        threat_id = "2147835234"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {17 9a a2 25 18 72 ?? ?? ?? 70 a2 0c 02 14 72 ?? ?? ?? 70 18 8d ?? ?? ?? 01 25 16 16 8c ?? ?? ?? 01 a2 25 17 08 a2 25 13 05 14 14 18 8d ?? ?? ?? 01 25 17 17 9c 25 13 06 17}  //weight: 10, accuracy: Low
        $x_1_2 = "Control_Run" wide //weight: 1
        $x_1_3 = "PXX00004" ascii //weight: 1
        $x_1_4 = "BookInformation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_SP_2147835407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.SP!MTB"
        threat_id = "2147835407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 7b 25 00 00 04 08 6f ?? ?? ?? 0a 13 04 08 12 00 28 ?? ?? ?? 0a 6b 11 04 7b 3d 00 00 04 5a 69 12 00 28 ?? ?? ?? 0a 6b 11 04 7b 3e 00 00 04 5a 69 73 1e 00 00 0a 6f ?? ?? ?? 0a 00 08 12 00 28 ?? ?? ?? 0a 6b 11 04 7b 3f 00 00 04 5a 69 12 00 28 ?? ?? ?? 0a 6b 11 04 7b 40 00 00 04 5a 69 73 21 00 00 0a 6f ?? ?? ?? 0a 00 00 00 07 6f ?? ?? ?? 0a 3a 6b ff ff ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MI_2147837289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MI!MTB"
        threat_id = "2147837289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {b8 57 00 07 80 c3 22 02 28 09 00 00 0a 00 2a 3e 02 28 09 00 00 0a 00 02 03 7d 01 00 00 04 2a 22 02 28}  //weight: 5, accuracy: High
        $x_1_2 = "S8abili8y" ascii //weight: 1
        $x_1_3 = "get_GetPatch" ascii //weight: 1
        $x_1_4 = "R5comm5nd" ascii //weight: 1
        $x_1_5 = "XoxoTor.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MI_2147837289_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MI!MTB"
        threat_id = "2147837289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 16 0c 2b 10 07 08 9a 6f ?? ?? ?? 0a 06 17 58 0a 08 17 58 0c 08 07 8e 69 32 ea}  //weight: 5, accuracy: Low
        $x_5_2 = "d718e911-e1e4-4881-93a4-aac720e9a7cb" ascii //weight: 5
        $x_5_3 = "xshw.Properties" ascii //weight: 5
        $x_1_4 = "selfDelete" ascii //weight: 1
        $x_1_5 = "webhook" ascii //weight: 1
        $x_1_6 = "KillProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MM_2147837290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MM!MTB"
        threat_id = "2147837290"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 11 03 11 01 11 03 11 01 8e 69 5d 91 03 11 03 91 61 d2 9c 38 ?? ?? ?? ff 11 04 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "DestroyPublisher" ascii //weight: 1
        $x_1_3 = "EnableProxy" ascii //weight: 1
        $x_1_4 = "ManagePublisher" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "RemoveProxy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MM_2147837290_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MM!MTB"
        threat_id = "2147837290"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 9f a2 2b 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 b0 00 00 00 30 00 00 00 5e 01 00 00 19 03 00 00 b9 01 00 00 1b 00 00 00 4a}  //weight: 10, accuracy: High
        $x_5_2 = "c65e7525-df4f-4c24-acfd-40da2d183cd8" ascii //weight: 5
        $x_1_3 = "L00000" ascii //weight: 1
        $x_1_4 = "Control_Run" wide //weight: 1
        $x_1_5 = "K000001" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MN_2147837291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MN!MTB"
        threat_id = "2147837291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 19 2d 05 26 16 0d 2b 03 0c 2b f9 08 12 03 28 ?? ?? ?? 0a 06 03 07 28 ?? ?? ?? 06 6f ?? ?? ?? 0a}  //weight: 10, accuracy: Low
        $x_10_2 = {3a 00 2f 00 2f 00 34 00 35 00 2e 00 31 00 33 00 39 00 2e 00 31 00 30 00 35 00 2e 00 32 00 32 00 38 00 2f 00 [0-16] 2e 00 6a 00 70 00 65 00 67 00}  //weight: 10, accuracy: Low
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "$8fae485d-6dbb-4ead-9ffc-853544b60994" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MN_2147837291_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MN!MTB"
        threat_id = "2147837291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 15 a2 09 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 51 00 00 00 08 00 00 00 30 00 00 00 2b 00 00 00 24 00 00 00 85 00 00 00 16}  //weight: 10, accuracy: High
        $x_5_2 = "d8e8ab50-1a01-4e2b-8ba6-b8d03e9febdb" ascii //weight: 5
        $x_1_3 = "Jambo" ascii //weight: 1
        $x_1_4 = "Kursovaya_Tanchiki.Properties" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "Form2_KeyDown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MN_2147837291_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MN!MTB"
        threat_id = "2147837291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#fdgdfadgd.dll#" ascii //weight: 1
        $x_1_2 = "CRYPT_USER_PROTECTED" ascii //weight: 1
        $x_1_3 = "KeepExtraPEData" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "GetFileLock" ascii //weight: 1
        $x_1_9 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_10 = "DynamicDllInvokeType" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_SNP_2147838219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.SNP!MTB"
        threat_id = "2147838219"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 50 8e 69 17 58 8d 09 00 00 02 0a 16 0b 2b 10 00 06 07 7e 04 00 00 04 07 9a a2 00 07 17 58 0b 07 7e 04 00 00 04 8e 69 fe 04 0c 08 2d e2 02 06 51 2a}  //weight: 2, accuracy: High
        $x_1_2 = "VuWm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MX_2147838927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MX!MTB"
        threat_id = "2147838927"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a d2 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d dd}  //weight: 10, accuracy: Low
        $x_2_2 = "This application will kill and resurrect any active network" wide //weight: 2
        $x_2_3 = "snapshot is taken ot the connectivity" wide //weight: 2
        $x_2_4 = "NetworkAssassin.Samples.CoffeeMaker" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAZ_2147900097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAZ!MTB"
        threat_id = "2147900097"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 95 a2 3d 09 03 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9f 00 00 00 27 00 00 00 61 02}  //weight: 1, accuracy: High
        $x_1_2 = "c2d9949d-d9ba-46ae-8468-6ad0c35b943c" ascii //weight: 1
        $x_1_3 = "Jambo" ascii //weight: 1
        $x_1_4 = "txtLogin_KeyPress" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "tabControl1" ascii //weight: 1
        $x_1_7 = "GetExcelProcessAndKill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpySnake_MAH_2147901449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpySnake.MAH!MTB"
        threat_id = "2147901449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 12 04 28 ?? ?? ?? 0a 07 08 02 08 91 6f ?? ?? ?? 0a de 0b 11 04 2c 06 09 28 ?? ?? ?? 0a dc 08 25 17 59 0c 16 fe 02 13 05 2b 04 13 04 2b d1 11 05 2d 02 2b 05 2b c3 0d 2b c3 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 13 06 2b 03 26 2b 9c 11 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "toraech.com" wide //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

