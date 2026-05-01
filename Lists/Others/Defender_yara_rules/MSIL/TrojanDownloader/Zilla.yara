rule TrojanDownloader_MSIL_Zilla_AR_2147957570_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Zilla.AR!MTB"
        threat_id = "2147957570"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_12_1 = {11 0b 16 14 16 13 1a 12 1a 16 16 13 1b 12 1b 16 6f}  //weight: 12, accuracy: High
        $x_8_2 = {16 fe 01 13 36 11 36 2c 19 11 34 11 0c 28 1c 01 00 06}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Zilla_SX_2147965613_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Zilla.SX!MTB"
        threat_id = "2147965613"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {11 04 11 05 9a 13 06 11 06 72 ?? ?? 00 70 6f ?? 00 00 0a 2c 04 17 0c 2b 4d 08 2c 4a 11 06 6f ?? 00 00 0a 6f ?? 00 00 0a 16 31 3b 11 06 17 8d 72 00 00 01 25 16}  //weight: 30, accuracy: Low
        $x_10_2 = "DownloadAndExecutePay2PayloadAsync" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Zilla_AMTB_2147968265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Zilla!AMTB"
        threat_id = "2147968265"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7d 0f 00 00 04 12 00 15 7d 0e 00 00 04 12 00 7c 0f 00 00 04 12 00 28 01 00 00 2b 12 00 7c 0f 00 00 04 28 44 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_2_2 = {28 42 00 00 0a 7d 0f 00 00 04 12 00 15 7d 0e 00 00 04 12 00 7c 0f 00 00 04 12 00 28 01 00 00 2b 12 00 7c 0f 00 00 04}  //weight: 2, accuracy: High
        $x_4_3 = {28 16 00 00 06 2c 07 28 19 00 00 06 2b 05 28 18 00 00 06 28 1a 00 00 06 6f 3e 00 00 0a}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

