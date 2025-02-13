rule TrojanDownloader_MSIL_PSDownload_AAB_2147850127_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PSDownload.AAB!MTB"
        threat_id = "2147850127"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PSDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 06 08 91 9c 06 08 09 9c 07 17 58 0b 08 17 59 0c 07 16 2d cd 08 32 d7 06 2a 0a 38 ?? ?? ?? ?? 06 2b b5 06 2b bb 0c}  //weight: 2, accuracy: Low
        $x_2_2 = "FromBase64String" ascii //weight: 2
        $x_2_3 = "HttpClient" ascii //weight: 2
        $x_2_4 = "GetString" ascii //weight: 2
        $x_2_5 = "ReadAsByteArrayAsync" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

