rule TrojanDownloader_MSIL_RemcosRAT_B_2147824431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RemcosRAT.B!MTB"
        threat_id = "2147824431"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {08 25 17 59 0c 16 fe ?? 0d 09 2c ?? 2b ?? 2b ?? 6f ?? ?? ?? 0a 2b ?? 17 2b ?? 16 2b ?? 2d ?? 07 6f ?? ?? ?? 0a 2b 00 07 06 08 91 2b}  //weight: 15, accuracy: Low
        $x_1_2 = "AddSeconds" ascii //weight: 1
        $x_1_3 = "DateTime" ascii //weight: 1
        $x_1_4 = "SecurityProtocol" ascii //weight: 1
        $x_1_5 = "WebRequest" ascii //weight: 1
        $x_1_6 = "GetResponseStream" ascii //weight: 1
        $x_1_7 = "op_GreaterThan" ascii //weight: 1
        $x_1_8 = "op_LessThan" ascii //weight: 1
        $x_1_9 = "get_Now" ascii //weight: 1
        $x_1_10 = "ToArray" ascii //weight: 1
        $x_1_11 = "GetType" ascii //weight: 1
        $x_1_12 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_RemcosRAT_D_2147826061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RemcosRAT.D!MTB"
        threat_id = "2147826061"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {0a 0b 00 73 ?? ?? ?? 0a 0c 16 2d ?? 00 2b ?? 2b ?? 2b ?? 00 2b ?? 2b ?? 16 2c ?? 26 de ?? 07 2b ?? 08 2b ?? 6f ?? ?? ?? 0a 2b ?? 08 2b ?? 6f ?? ?? ?? 0a 2b ?? 0d 2b 4a 00 17 2c ?? 00 2b ?? 38 ?? ?? ?? 00 00 06 02 6f}  //weight: 15, accuracy: Low
        $x_1_2 = "GetTypes" ascii //weight: 1
        $x_1_3 = "ToList" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "BufferedStream" ascii //weight: 1
        $x_1_6 = "CopyTo" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "CompressionMode" ascii //weight: 1
        $x_1_9 = "GetMethods" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_RemcosRAT_G_2147829377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RemcosRAT.G!MTB"
        threat_id = "2147829377"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 8e 69 5d 91 ?? [0-2] 91 61 d2 9c [0-2] 17 58 [0-5] 8e 69 32}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "GetDomain" ascii //weight: 1
        $x_1_7 = "CreateDelegate" ascii //weight: 1
        $x_1_8 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RemcosRAT_H_2147834225_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RemcosRAT.H!MTB"
        threat_id = "2147834225"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 06 6f ?? 00 00 0a 17 3e ?? 00 00 00 07 72 ?? 00 00 70 6f ?? 00 00 0a 0c 06 6f ?? 00 00 0a 6f ?? 00 00 0a 16 3e ?? 00 00 00 08 72 ?? 00 00 70 6f ?? 00 00 0a 0d 06 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 17 6a 3e ?? 00 00 00 d0 ?? 00 00 01 28 ?? 00 00 0a 09 28 ?? 00 00 0a 74 ?? 00 00 01 13 04 06 6f ?? 00 00 0a 26 73 ?? 00 00 0a 11 04 28 ?? 00 00 0a 6f}  //weight: 2, accuracy: Low
        $x_1_3 = "GetResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RemcosRAT_I_2147837684_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RemcosRAT.I!MTB"
        threat_id = "2147837684"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 16 0d 2b 16 06 09 28 ?? 00 00 06 13 04 07 09 11 04 6f ?? 00 00 0a 09 18 58 0d 09 06 6f ?? 00 00 0a 32 ?? 07 6f ?? 00 00 0a 28 ?? 00 00 2b 0c 08 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {02 03 18 6f ?? 00 00 0a 1f 10 28}  //weight: 2, accuracy: Low
        $x_2_3 = {0a 0c 07 6f ?? 00 00 0a 0d 16 13 04 2b 18 09 11 04 6f ?? 00 00 0a 13 05 08 11 05 6f ?? 00 00 0a 11 04 17 58 13 04 11 04 09 6f ?? 00 00 0a 32 de 14 08 28 03 00 00 2b 0d de 17 07 2c 06 07 6f ?? 00 00 0a dc 06 2c 06 06 6f ?? 00 00 0a dc 26 de 8d 09 2a}  //weight: 2, accuracy: Low
        $x_1_4 = "GetResponseStream" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RemcosRAT_C_2147844620_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RemcosRAT.C!MTB"
        threat_id = "2147844620"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 00 06 02 6f ?? ?? ?? 0a 0b 00 73 ?? ?? ?? 0a 0c 00 07 08 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 0d de}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0c 00 08 07 1f 00 02 73 ?? ?? ?? 0a 0a 00 73 ?? ?? ?? 0a 0b 00 06 16 73 ?? ?? ?? 0a 73}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 0b 00 07 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0c 08 2c ?? 07 0d de}  //weight: 1, accuracy: Low
        $x_1_4 = "CopyTo" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
        $x_1_6 = "GetMethods" ascii //weight: 1
        $x_1_7 = "ToList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RemcosRAT_A_2147844633_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RemcosRAT.A!MTB"
        threat_id = "2147844633"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 0a 0d 06 09 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 16 2d cf 18 2c cc 00 06 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 10 00 02 13 04 de 2c 28 ?? 00 00 0a 2b af 6f ?? 00 00 0a 2b af 0b 2b ae 73 ?? 00 00 0a 2b a9 0c}  //weight: 1, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
        $x_1_6 = "GetResponseStream" ascii //weight: 1
        $x_1_7 = "NextBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

