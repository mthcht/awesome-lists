rule TrojanDownloader_MSIL_SnakeKeylogger_G_2147824429_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/SnakeKeylogger.G!MTB"
        threat_id = "2147824429"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {0a 0a 00 06 02 73 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b de ?? 48 00 20 ?? ?? ?? 00 2b ?? ?? 2b ?? 28 ?? ?? ?? 0a 2b ?? ?? de ?? 26 ?? ?? de 00 73}  //weight: 15, accuracy: Low
        $x_1_2 = "AddSeconds" ascii //weight: 1
        $x_1_3 = "DateTime" ascii //weight: 1
        $x_1_4 = "SecurityProtocol" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
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

rule TrojanDownloader_MSIL_SnakeKeylogger_I_2147831652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/SnakeKeylogger.I!MTB"
        threat_id = "2147831652"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 07 09 07 8e 69 5d 91 02 09 91 61 d2 9c 09 17 58 0d 09 02 8e 69 32}  //weight: 2, accuracy: High
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "get_ASCII" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_SnakeKeylogger_H_2147844621_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/SnakeKeylogger.H!MTB"
        threat_id = "2147844621"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 16 02 8e 69 ?? 3a ?? 00 00 00 26 26 26 38 ?? 00 00 00 28 ?? 00 00 0a 38 00 00 00 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 0a 0b 20 00 ?? 00 00 8d ?? 00 00 01 0c 16 0d 07 08 16 08 8e 69 6f ?? 00 00 0a 0d 12 ?? 08 09 28 ?? 00 00 06 09 16 fe ?? 13 ?? 11 ?? 3a ?? ?? ff ff 11 05 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {00 00 0a 74 0a 00 00 01 ?? 3a ?? 00 00 00 26 06 38 ?? 00 00 00 0a 38 ?? ff ff ff 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_SnakeKeylogger_CXFP_2147852025_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/SnakeKeylogger.CXFP!MTB"
        threat_id = "2147852025"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 00 77 00 77 00 2e 00 6c 00 6f 00 67 00 70 00 61 00 73 00 74 00 61 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 73 00 74 00 65 00 2f 00 72 00 61 00 77 00 2f 00 62 00 33 00 66 00 65 00 36 00 31 00 63 00 63 00 2d 00 65 00 35 00 63 00 63 00 2d 00 34 00 62 00 34 00 63 00 2d 00 39 00 66 00 33 00 33 00 2d 00 35 00 32 00 37 00 34 00 64 00 63 00 30 00 66 00 37 00 35 00 36 00 66 00 2e 00 74 00 78 00 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

