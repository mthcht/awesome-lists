rule TrojanDownloader_MSIL_LummaC_CCJC_2147924101_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LummaC.CCJC!MTB"
        threat_id = "2147924101"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 09 17 73 ?? ?? ?? ?? 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 10 00 de 18 11 05 2c 07 11 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_LummaC_CCJN_2147926891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LummaC.CCJN!MTB"
        threat_id = "2147926891"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "nA+7EPJSfO1KlqLax9AZug==" ascii //weight: 5
        $x_5_2 = "S3ojTUxsWUA5U1RKRntifWdKbEw=" ascii //weight: 5
        $x_1_3 = "TAOHjFnKFWaLV7zplOhnmw==" ascii //weight: 1
        $x_1_4 = "wd4tCV9/1BbPVujoRm5dpQ==" ascii //weight: 1
        $x_1_5 = "fsJfePaL9PhqXLKP0k3sVQ==" ascii //weight: 1
        $x_1_6 = "VWoyEkgPh+oToxlPlK7sVw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_LummaC_CCJR_2147936690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LummaC.CCJR!MTB"
        threat_id = "2147936690"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 36 11 2c 25 17 58 13 2c 11 18 11 14 91 11 18 11 14 17 58 91 1e 62 60 d1 9d 11 14 18 58 13 14 11 14 11 0b 32 da}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_LummaC_CCJS_2147936691_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LummaC.CCJS!MTB"
        threat_id = "2147936691"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "PayloadManager+<FetchPayloadAsync>" ascii //weight: 5
        $x_1_2 = "PayloadManager+<FetchPayloadFromFileAsync>" ascii //weight: 1
        $x_1_3 = "PayloadManager+<FetchPayloadFromNetworkAsync>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

