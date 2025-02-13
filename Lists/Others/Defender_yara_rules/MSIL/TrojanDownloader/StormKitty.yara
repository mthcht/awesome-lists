rule TrojanDownloader_MSIL_StormKitty_A_2147831847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/StormKitty.A!MTB"
        threat_id = "2147831847"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 11 03 11 01 6f ?? 00 00 0a 11 02 6f ?? 00 00 0a 28 ?? 00 00 0a 74 ?? 00 00 01 28 05 00 00 06 38}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 70 1a 3a 58 00 00 00 26 38 00 00 00 00 72 ?? 00 00 70 13 02 38}  //weight: 2, accuracy: Low
        $x_2_3 = {8e 69 5d 91 02 11 03 91 61 d2 9c 38}  //weight: 2, accuracy: High
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "get_ASCII" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

