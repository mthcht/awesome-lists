rule TrojanDownloader_MSIL_Malgent_RP_2147912720_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Malgent.RP!MTB"
        threat_id = "2147912720"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Malgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 2d 1c 15 2c 19 08 07 09 18 6f 12 00 00 0a 1f 10 28 13 00 00 0a 6f 14 00 00 0a 09 18 58 0d 09 07 6f 15 00 00 0a 16 2d 1d 32 d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

