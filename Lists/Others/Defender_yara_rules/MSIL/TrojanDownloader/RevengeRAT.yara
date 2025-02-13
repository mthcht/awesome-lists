rule TrojanDownloader_MSIL_RevengeRAT_A_2147902477_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RevengeRAT.A!MTB"
        threat_id = "2147902477"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 17 9a 75 ?? 00 00 01 20 ?? ?? ?? 1a 28 ?? ?? 00 06 20 00 01 00 00 14 14 14 6f ?? ?? 00 0a a2 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

