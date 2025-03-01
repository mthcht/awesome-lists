rule TrojanDownloader_MSIL_njRAT_RDQ_2147846506_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/njRAT.RDQ!MTB"
        threat_id = "2147846506"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 07 09 06 08 18 5b 06 6f 16 00 00 0a 5d 6f 17 00 00 0a 61 d1 8c 16 00 00 01 28 18 00 00 0a 0b 08 18 58 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

