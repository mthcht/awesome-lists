rule TrojanDownloader_MSIL_WarzoneRat_AWZ_2147898390_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/WarzoneRat.AWZ!MTB"
        threat_id = "2147898390"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WarzoneRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 12 00 7e ?? 00 00 04 06 6f ?? 00 00 0a 00 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

