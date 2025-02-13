rule TrojanDownloader_MSIL_Ursu_RDA_2147892485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ursu.RDA!MTB"
        threat_id = "2147892485"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {17 6f 1f 00 00 0a 25 6f 1d 00 00 0a 17 6f 20 00 00 0a 6f 1d 00 00 0a 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ursu_AB_2147896264_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ursu.AB!MTB"
        threat_id = "2147896264"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 07 11 04 28 ?? 00 00 0a 16 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 11 06 12 04 28 ?? 00 00 0a 13 09 11 09 2d d1 08 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26 de 2b}  //weight: 5, accuracy: Low
        $x_1_2 = "WriteLine" ascii //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
        $x_1_4 = "ToInteger" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
        $x_1_6 = "FromStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

