rule TrojanDownloader_MSIL_RaccoonStealerV2_C_2147842198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RaccoonStealerV2.C!MTB"
        threat_id = "2147842198"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RaccoonStealerV2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 09 94 07 08 94 58 20 00 01 00 00 5d 94 13}  //weight: 2, accuracy: High
        $x_2_2 = {61 d2 9c 06 17 25}  //weight: 2, accuracy: High
        $x_1_3 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

