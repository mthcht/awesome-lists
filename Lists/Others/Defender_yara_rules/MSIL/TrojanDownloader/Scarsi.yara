rule TrojanDownloader_MSIL_Scarsi_RS_2147834870_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Scarsi.RS!MTB"
        threat_id = "2147834870"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 28 12 00 00 0a 72 51 00 00 70 6f 13 00 00 0a 08 28 12 00 00 0a 72 51 00 00 70 6f 13 00 00 0a 8e 69 5d 91 06 08 91 61 d2 6f 14 00 00 0a 08 17 58 0c 08 06 8e 69 32 c8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Scarsi_RS_2147834870_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Scarsi.RS!MTB"
        threat_id = "2147834870"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 a6 00 00 0a 72 15 0b 00 70 6f a7 00 00 0a 0d 08 8e 69 17 da 13 06 16 13 07 2b 17}  //weight: 1, accuracy: High
        $x_1_2 = {08 11 07 09 11 07 09 8e 69 5d 91 08 11 07 91 61 9c 11 07 17 d6 13 07 11 07 11 06 31 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Scarsi_NZT_2147837413_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Scarsi.NZT!MTB"
        threat_id = "2147837413"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 8e 69 5d 91 02 7b ?? 00 00 04 07 91 61 d2 6f ?? 00 00 0a 07 17 58 0b 07 02 7b ?? 00 00 04 8e 69 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Scarsi_ASI_2147842669_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Scarsi.ASI!MTB"
        threat_id = "2147842669"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scarsi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 09 11 00 11 05 11 00 91 11 0a 61 d2 9c 20 01 00 00 00 7e 46 00 00 04 7b 4a 00 00 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

