rule TrojanDownloader_MSIL_PsDownload_MA_2147809050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PsDownload.MA!MTB"
        threat_id = "2147809050"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fiiii" wide //weight: 1
        $x_1_2 = "iirrst.txt" wide //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "powershell" wide //weight: 1
        $x_1_6 = "-enc" wide //weight: 1
        $x_1_7 = "timer1_Tick" ascii //weight: 1
        $x_1_8 = "get_KeyCode" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "add_KeyDown" ascii //weight: 1
        $x_1_11 = "set_SuppressKeyPress" ascii //weight: 1
        $x_1_12 = "GetFolderPath" ascii //weight: 1
        $x_1_13 = "ToBase64String" ascii //weight: 1
        $x_1_14 = "GetBytes" ascii //weight: 1
        $x_1_15 = "DownloadString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PsDownload_NZT_2147837416_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PsDownload.NZT!MTB"
        threat_id = "2147837416"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 1c 2d 03 26 2b 03 0b 2b 00 06 16 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 17 2d 03 26 2b 03 0c 2b}  //weight: 1, accuracy: Low
        $x_1_2 = {38 00 39 00 2e 00 33 00 34 00 2e 00 32 00 37 00 2e 00 31 00 36 00 37 00 2f 00 77 00 69 00 72 00 65 00 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PsDownload_CXD_2147842014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PsDownload.CXD!MTB"
        threat_id = "2147842014"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 13 00 00 0a 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b 07 16 07 8e 69 28 ?? ?? ?? ?? 07 0c de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PsDownload_ABAS_2147849708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PsDownload.ABAS!MTB"
        threat_id = "2147849708"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 00 0a 0b 16 0a 2b 36 07 13 05 16 13 06 11 05 12 06 28 ?? 00 00 0a 07 09 06 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de 0c 11 06 2c 07 11 05 28 ?? 00 00 0a dc 06 18 58 0a 06 09 6f ?? 00 00 0a fe 04 13 07 11 07 2d bb 07 6f ?? 00 00 0a 28 ?? 00 00 0a 13 08 11 08}  //weight: 10, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
        $x_1_3 = "HttpResponseMessage" ascii //weight: 1
        $x_1_4 = "HttpClient" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "GetAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PsDownload_AAIX_2147852360_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PsDownload.AAIX!MTB"
        threat_id = "2147852360"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b 2d 2b 32 2b 33 72 bb 00 00 70 7e ?? 00 00 0a 2b 2e 2b 33 1c 2d 0d 26 dd ?? 00 00 00 2b 2f 15 2c f6 2b dc 2b 2b 2b f0 28 ?? 00 00 06 2b cd 28 ?? 00 00 0a 2b cc 07 2b cb 6f ?? 00 00 0a 2b c6 6f ?? 00 00 0a 2b cb 28 ?? 00 00 0a 2b c6 0b 2b ce 0c 2b d2}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PsDownload_PAK_2147929194_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PsDownload.PAK!MTB"
        threat_id = "2147929194"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 01 00 00 70 6f ?? 00 00 0a 06 72 17 00 00 70 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 28 ?? 00 00 0a 26}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

