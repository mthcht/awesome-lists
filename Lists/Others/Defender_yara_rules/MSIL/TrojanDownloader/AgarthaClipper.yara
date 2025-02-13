rule TrojanDownloader_MSIL_AgarthaClipper_A_2147900182_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgarthaClipper.A!MTB"
        threat_id = "2147900182"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgarthaClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 11 04 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 2b 6f ?? 00 00 0a 28 ?? 00 00 2b 02 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 06 26 14 14 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

