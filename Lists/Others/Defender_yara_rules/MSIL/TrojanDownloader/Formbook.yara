rule TrojanDownloader_MSIL_Formbook_ESA_2147818264_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Formbook.ESA!MTB"
        threat_id = "2147818264"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 02 07 91 6f ?? ?? ?? 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e7}  //weight: 1, accuracy: Low
        $x_1_2 = {0b 12 01 23 00 00 00 00 00 00 24 40 28 ?? ?? ?? 0a 0a 28 ?? ?? ?? 0a 0b 12 01 23 00 00 00 00 00 00 24 40 28 ?? ?? ?? 0a 0a}  //weight: 1, accuracy: Low
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Formbook_KAC_2147819562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Formbook.KAC!MTB"
        threat_id = "2147819562"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d6 0b 07 11 ?? 31 ?? 16 00 11 ?? 11 ?? 07 94 b4 6f ?? ?? ?? 0a ?? 07 17}  //weight: 1, accuracy: Low
        $x_1_2 = "powershell" ascii //weight: 1
        $x_1_3 = "(New-Object Net.WebClient)" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "ToInteger" ascii //weight: 1
        $x_1_6 = "StringBuilder" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
        $x_1_8 = "ToString" ascii //weight: 1
        $x_1_9 = "Substring" ascii //weight: 1
        $x_1_10 = "CompareString" ascii //weight: 1
        $x_1_11 = "AddSeconds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Formbook_KAD_2147820441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Formbook.KAD!MTB"
        threat_id = "2147820441"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 93 28 ?? ?? ?? 06 1a 59 0c 20 ?? ?? ?? 00 0d 09 08 2f ?? 08 09 59 0c 2b ?? 16 08 31 ?? 08 09 58 0c 06 07 08 d1 9d 07 17 58 0b 07 06 8e 69 32}  //weight: 1, accuracy: Low
        $x_1_2 = {06 02 07 9a 28 ?? ?? ?? 06 d1 0c 12 ?? 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 07 17 58 0b 07 02 8e 69 32}  //weight: 1, accuracy: Low
        $x_1_3 = {06 07 02 07 28 ?? ?? ?? 06 07 28 ?? ?? ?? 06 61 d1 9d 07 17 58 0b 07 02 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {07 06 08 8f ?? ?? ?? 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 08 17 59 0c 08 15 30}  //weight: 1, accuracy: Low
        $x_1_5 = {07 08 9a 28 ?? ?? ?? 06 0d 06 08 09 28 ?? ?? ?? 06 9c 08 17 58 0c 08 06 8e 69 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_MSIL_Formbook_KAI_2147824428_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Formbook.KAI!MTB"
        threat_id = "2147824428"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 1c 72 f3 ?? ?? 70 7e ?? ?? ?? 04 2b ?? 2b ?? 2b ?? 74 ?? ?? ?? 1b 2b ?? 2b ?? 2b ?? 2a 28 ?? ?? ?? 06 2b ?? 6f ?? ?? ?? 0a 2b e2}  //weight: 1, accuracy: Low
        $x_1_2 = {16 2d 1a 2b ?? 2b ?? 2b ?? 91 6f 25 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {07 6f 26 00 00 0a 0a 06 13 ?? 16 2d c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Formbook_KAJ_2147826063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Formbook.KAJ!MTB"
        threat_id = "2147826063"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 02 6f 0a ?? ?? 0a ?? 2d ?? 26 2b ?? 0b 2b ?? 73 ?? ?? ?? 0a 0c 07 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 0d de}  //weight: 1, accuracy: Low
        $x_1_2 = {6f 14 00 00 0a 1a 2d ?? 26 06 2b ?? 0a 2b ?? 2a 1a 00 28 13 00 00 0a 28 01 00 00 06}  //weight: 1, accuracy: Low
        $x_1_3 = {02 06 6f 15 00 00 0a 02 fe ?? ?? ?? ?? 06 73 ?? ?? ?? 0a 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 16 6f ?? ?? ?? 0a ?? 2d 07 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Formbook_KAK_2147828367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Formbook.KAK!MTB"
        threat_id = "2147828367"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 91 06 [0-2] 91 61 d2 9c 2b 03 0c 2b ?? [0-2] 17 58 [0-2] 2b 03 0b 2b ?? [0-2] 06 8e 69 32}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 0a 25 02 73 ?? 00 00 0a 6f ?? 00 00 0a 0a 6f ?? 00 00 0a 06 0b de}  //weight: 1, accuracy: Low
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "CreateDelegate" ascii //weight: 1
        $x_1_7 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Formbook_KAA_2147846917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Formbook.KAA!MTB"
        threat_id = "2147846917"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://192.227.183.170/mac/" wide //weight: 2
        $x_2_2 = "Vcxxdtazprl.Rgezlbkwxqrzzdgker" wide //weight: 2
        $x_2_3 = "Wqwbckti" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Formbook_RDJ_2147848754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Formbook.RDJ!MTB"
        threat_id = "2147848754"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xqixjyhncoafii" ascii //weight: 1
        $x_1_2 = "Ltzmykmejtyc" ascii //weight: 1
        $x_1_3 = "Yuqndazgmqoc" ascii //weight: 1
        $x_1_4 = "9b5a9a9c81f741a7234ca3baae62dc56" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Formbook_RDK_2147850784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Formbook.RDK!MTB"
        threat_id = "2147850784"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 19 00 00 0a 6f 1a 00 00 0a 00 06 6f 1b 00 00 0a 02 16 02 8e 69 6f 1c 00 00 0a 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Formbook_RDM_2147888301_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Formbook.RDM!MTB"
        threat_id = "2147888301"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 03 00 00 0a 6f 04 00 00 0a 28 0e 00 00 06 6f 05 00 00 0a 6f 06 00 00 0a 13 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Formbook_KAL_2147899740_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Formbook.KAL!MTB"
        threat_id = "2147899740"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 05 08 11 05 91 11 04 11 05 11 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 05 17 58 13 05 11 05 16 2d ?? 08 8e 69 32}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Formbook_KAF_2147899874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Formbook.KAF!MTB"
        threat_id = "2147899874"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 04 08 11 04 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 11 04 17 58 13 04 11 04 08 8e 69 32}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

