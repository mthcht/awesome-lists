rule TrojanDownloader_MSIL_Iusdat_A_2147831382_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Iusdat.A!MTB"
        threat_id = "2147831382"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Iusdat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 da 51 00 70 0a 06 28 ?? ?? 00 0a 0b 07 6f ?? ?? 00 0a 0c 08 6f ?? ?? 00 0a 73 ?? ?? 00 0a 6f ?? 00 00 0a 26 73 ?? 00 00 0a 06 28 ?? ?? 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

