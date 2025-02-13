rule Trojan_MSIL_TrojanDropper_Phonzy_2147780365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TrojanDropper.Phonzy.ADG!MTB"
        threat_id = "2147780365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TrojanDropper"
        severity = "Critical"
        info = "ADG: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "7cthLvdl3ILycPbsXQckBX2FVvHQeg3HbezwF3FKmw79un3KZxklqWu" ascii //weight: 4
        $x_4_2 = "xVTQqLsw0kmxHrGjIFBqwIoxKZAqYa5pRLwVx5opsAF2t7uQoYBPa3cJOiEDds6s" ascii //weight: 4
        $x_4_3 = "ATHh6g2suxIKjqSa6qb8Z7FoG9Wlwf9ABr" ascii //weight: 4
        $x_4_4 = "ki38BePBzpTHd3LXTjFVzdvBOQXaMHlWYn4wmFUSnMKxj9SGkLDIYw7feaaihtuSGrRgKmc45n" ascii //weight: 4
        $x_3_5 = "DecrypterData" ascii //weight: 3
        $x_3_6 = "TaskScheduler" ascii //weight: 3
        $x_2_7 = "Windows\\Media\\Log" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_TrojanDropper_Agent_2147797973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TrojanDropper.Agent.MA!MTB"
        threat_id = "2147797973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TrojanDropper"
        severity = "Critical"
        info = "MA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://q1212.me/Vv/" ascii //weight: 1
        $x_1_2 = "Form1_Load" ascii //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "ToString" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
        $x_1_6 = "stop svchost" ascii //weight: 1
        $x_1_7 = "UploadString" ascii //weight: 1
        $x_1_8 = "WM_KEYDOWN" ascii //weight: 1
        $x_1_9 = "get_MachineName" ascii //weight: 1
        $x_1_10 = "GetHostName" ascii //weight: 1
        $x_1_11 = "txthistory" ascii //weight: 1
        $x_1_12 = "IPHostEntry" ascii //weight: 1
        $x_1_13 = "GetHostEntry" ascii //weight: 1
        $x_1_14 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TrojanDropper_Agent_2147807756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TrojanDropper.Agent.MC!MTB"
        threat_id = "2147807756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TrojanDropper"
        severity = "Critical"
        info = "MC: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a81ad26b-cff5-4832-a1d2-413cc35c5a8b" ascii //weight: 1
        $x_1_2 = "HashStealer" ascii //weight: 1
        $x_1_3 = "ZipFileExtensions" ascii //weight: 1
        $x_1_4 = "Antimalware Service Executable" ascii //weight: 1
        $x_1_5 = "Host Process for Windows Services" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
        $x_1_7 = "VirtualAlloc" ascii //weight: 1
        $x_1_8 = "CreateFile" ascii //weight: 1
        $x_1_9 = "get_ProcessName" ascii //weight: 1
        $x_1_10 = "WriteLine" ascii //weight: 1
        $x_1_11 = "DebuggableAttribute" ascii //weight: 1
        $x_1_12 = "GetString" ascii //weight: 1
        $x_1_13 = "MemoryStream" ascii //weight: 1
        $x_1_14 = "GetTypes" ascii //weight: 1
        $x_1_15 = "WriteAllBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TrojanDropper_PSE_2147831470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TrojanDropper.PSE!MTB"
        threat_id = "2147831470"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TrojanDropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 16 9a 28 0e 00 00 0a 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 0c 72 ?? ?? ?? 70 08 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 00 72 ?? ?? ?? 70 1b 8d ?? ?? ?? 01 13 0b 11 0b 16 72 ?? ?? ?? 70 a2 11 0b 17 08 a2 11 0b 18 72 ?? ?? ?? 70 a2 11 0b 19 02 16 9a a2 11 0b 1a 72 ?? ?? ?? 70 a2 11 0b 28 ?? ?? ?? 0a 16 28 ?? ?? ?? 06 00 72 ?? ?? ?? 70 28 ?? ?? ?? 06 00 08 72 ?? ?? ?? 70 17}  //weight: 5, accuracy: Low
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "LaunchProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

