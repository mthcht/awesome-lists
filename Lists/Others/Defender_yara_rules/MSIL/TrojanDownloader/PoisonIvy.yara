rule TrojanDownloader_MSIL_PoisonIvy_A_2147831484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PoisonIvy.A!MTB"
        threat_id = "2147831484"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PoisonIvy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 9a 6f ?? 00 00 0a 28 ?? 00 00 0a 13 04 08 09 11 04 9c 00 09 17 58 0d 09 07 8e 69 fe}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

