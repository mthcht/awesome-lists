rule TrojanDownloader_MSIL_DCRat_B_2147824434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DCRat.B!MTB"
        threat_id = "2147824434"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 03 fe ?? 16 fe ?? 0d 09 2d ?? 06 28 ?? ?? ?? 2b 17 8d ?? ?? ?? 01 6f ?? ?? ?? 0a 13 ?? 2b ?? 11 ?? 2a 52 00 03 17 58 8d ?? ?? ?? 01 0a 16 0b 2b ?? 00 00 06 07 02 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 9d 00 de ?? 0c 00 de ?? 00 07 17 58}  //weight: 1, accuracy: Low
        $x_1_2 = {0b 07 02 6f 28 00 02 2c ?? 20 ?? ?? ?? 81 0a 16 0b 2b ?? 02 07 6f ?? ?? ?? 0a 06 61 20 ?? ?? ?? 01 5a 0a 07 17 58}  //weight: 1, accuracy: Low
        $x_1_3 = {00 03 04 05 0e 04 28 ?? 00 00 0a 00 2a}  //weight: 1, accuracy: Low
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "FlushFinalBlock" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_DCRat_F_2147830887_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DCRat.F!MTB"
        threat_id = "2147830887"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 20 00 00 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 20 ?? ?? ?? 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 20 ?? ?? ?? 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 20 ?? ?? ?? 00 28 ?? 00 00 06 1f 25 28 ?? 00 00 0a 28 ?? 00 00 0a 20 ?? ?? ?? 00 28 ?? 00 00 06 72 01 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 07 28 ?? 00 00 0a 39 ?? 00 00 00 07 28 ?? 00 00 0a dd 06 00 00 00 26 dd 00 00 00 00 73 ?? 00 00 0a 06 07 28}  //weight: 2, accuracy: Low
        $x_1_2 = "IsInRole" ascii //weight: 1
        $x_1_3 = "set_Verb" ascii //weight: 1
        $x_1_4 = "set_FileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_DCRat_H_2147833623_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DCRat.H!MTB"
        threat_id = "2147833623"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 25 16 6f ?? 00 00 0a 74 ?? 00 00 01 [0-2] 25 [0-2] 72 ?? 00 00 70 6f ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 75 ?? 00 00 01 [0-2] 25 d0 ?? 00 00 01 28 ?? 00 00 0a [0-2] 28 ?? 00 00 06 74 ?? 00 00 01 6f ?? 00 00 0a 25 18 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {8e 69 5d 91 03 [0-2] 91 61 d2 9c}  //weight: 2, accuracy: Low
        $x_1_3 = "get_ASCII" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_DCRat_G_2147844626_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DCRat.G!MTB"
        threat_id = "2147844626"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set_FileName" ascii //weight: 1
        $x_1_2 = "set_Arguments" ascii //weight: 1
        $x_1_3 = "set_WindowStyle" ascii //weight: 1
        $x_1_4 = "set_CreateNoWindow" ascii //weight: 1
        $x_2_5 = "powershell" wide //weight: 2
        $x_2_6 = "-EncodedCommand" wide //weight: 2
        $x_2_7 = "QBlAG4AdABMAGkAcwB0ACAAIgBBAGQAZAAtAFQAeQBwAGUAIAAtAEEAcwB" wide //weight: 2
        $x_2_8 = "zAGUAbQBiAGwAeQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzA" wide //weight: 2
        $x_2_9 = "BTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAcABvAHcAZQByAH" wide //weight: 2
        $x_2_10 = "MAaABlAGwAbAAgAC0AVwBpAG4AZABvAHcAUwB0AHkAbABlACAASABpAGQAZABlAG4AIAAtAEEAcgBnAHUAb" wide //weight: 2
        $x_2_11 = "EEAZABkAC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGU" wide //weight: 2
        $x_2_12 = "BFAHgAYwBsAHUAcwBpAG8AbgBQAGEAdABoACAAQAAoACQAZQ" wide //weight: 2
        $x_2_13 = "BuAHYAOgBVAHMAZQByAFAAcgBvAGYAaQBsAGUALAAkAGUAbgB2ADoAUwB5AHMAdABlAG0ARAByAGkAdgBlACk" wide //weight: 2
        $x_2_14 = "AKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQ" wide //weight: 2
        $x_2_15 = "FAAYQB0AGgAIAAkAGUAbgB2ADoAQQBwAHAARABhAHQAYQ" wide //weight: 2
        $x_2_16 = "AUABhAHQAaAAgACQAZQBuAHYAOgBUAGUAbQBw" wide //weight: 2
        $x_2_17 = "FMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEYAaQBsAGUAUABhAHQAaA" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_DCRat_O_2147849330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DCRat.O!MTB"
        threat_id = "2147849330"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 f5 02 28 09 07 00 00 00 00 00 00 00 00 00 00 01 00 00 00 53 00 00 00 1a 00 00 00 2e 00 00 00 ac}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "SpecialFolder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_DCRat_ABV_2147896630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DCRat.ABV!MTB"
        threat_id = "2147896630"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {26 16 28 24 ?? ?? 0a 72 21 ?? ?? 70 28 25 ?? ?? 0a 26 17 0c 16 44 00 73 0e ?? ?? 06 0a 28 23 ?? ?? 0a 0b 1f 1a 28 24 ?? ?? 0a 72 0d ?? ?? 70 28 25 ?? 00 0a}  //weight: 4, accuracy: Low
        $x_1_2 = "DownloadFileAsync" ascii //weight: 1
        $x_1_3 = "GetFolderPath" ascii //weight: 1
        $x_1_4 = "Task27Loader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_DCRat_Q_2147900472_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DCRat.Q!MTB"
        threat_id = "2147900472"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 0a de 03 26 de ca 06 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 2b 6f ?? 00 00 0a 28 ?? 00 00 2b 14 14 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_DCRat_R_2147900524_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DCRat.R!MTB"
        threat_id = "2147900524"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 8e 69 17 5b 8d ?? 00 00 01 0a 16 0b}  //weight: 2, accuracy: Low
        $x_2_2 = {06 07 17 5b 7e ?? 00 00 0a a4 ?? 00 00 01 07 17 58 0b 07 02 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_DCRat_U_2147917669_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DCRat.U!MTB"
        threat_id = "2147917669"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 8e 69 8d ?? 00 00 01 0a 03 6f ?? 00 00 0a 0b 16 0c}  //weight: 2, accuracy: Low
        $x_4_2 = {06 08 02 08 91 07 08 07 8e 69 5d 93 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 0d 09}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_DCRat_X_2147918467_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DCRat.X!MTB"
        threat_id = "2147918467"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 19 9a 74 ?? 00 00 02 07 1b 9a 28 ?? 00 00 0a 07 18 9a 28 ?? ?? 00 0a 07 1c 9a 14 72 ?? ?? 00 70 18 8d ?? 00 00 01 25 16 72 ?? ?? 00 70 a2 25 17 7e ?? ?? 00 0a a2 14 14 14 28 ?? 00 00 0a 14 72 ?? ?? 00 70 18 8d ?? 00 00 01 25 16 72 ?? ?? 00 70 a2 25 17 7e ?? ?? 00 0a a2 14 14 14 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_DCRat_MG_2147922780_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DCRat.MG!MTB"
        threat_id = "2147922780"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 25 00 00 06 72 01 00 00 70 6f 08 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

