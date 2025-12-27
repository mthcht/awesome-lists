rule TrojanDownloader_MSIL_Injuke_RDA_2147837698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Injuke.RDA!MTB"
        threat_id = "2147837698"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6db56c9a-29bf-4770-b361-0eb92861d007" ascii //weight: 1
        $x_1_2 = "Traffic monitoring application" ascii //weight: 1
        $x_1_3 = "sFZ6sCFOOe29HRBl5k.2ZWQ07SXtcF3ALkj2E" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "LoadLibrary" ascii //weight: 1
        $x_1_6 = "GetProcAddress" ascii //weight: 1
        $x_1_7 = "GetDelegateForFunctionPointer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Injuke_AIK_2147844093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Injuke.AIK!MTB"
        threat_id = "2147844093"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 1f 00 00 70 28 32 00 00 06 19 2d 1c 26 28 26 00 00 0a 06 6f 27 00 00 0a 28 28 00 00 0a 28 30 00 00 06 16 2c 06 26 de 09 0a 2b e2 0b 2b f8}  //weight: 1, accuracy: High
        $x_1_2 = {0b 2b f8 02 06 91 18 2d 15 26 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Injuke_ARR_2147953378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Injuke.ARR!MTB"
        threat_id = "2147953378"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_25_1 = {04 11 05 07 11 05 91 28 ?? ?? ?? ?? 11 05 17 58 13 05 11 05 07 8e 69 32 e2}  //weight: 25, accuracy: Low
        $x_15_2 = {07 2c 06 07 6f ?? ?? ?? 0a dc 06 28 ?? ?? ?? 06 2c 0c 72 85 04 00 70 28 ?? ?? ?? 0a 2b 0a 72}  //weight: 15, accuracy: Low
        $x_10_3 = {08 7e 07 00 00 04 07 6f ?? ?? ?? ?? de 0a 08 2c 06}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

