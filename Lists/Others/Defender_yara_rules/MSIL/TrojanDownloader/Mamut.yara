rule TrojanDownloader_MSIL_Mamut_SO_2147892528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Mamut.SO!MTB"
        threat_id = "2147892528"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 9a 00 00 06 16 9a 75 19 00 00 1b 0d 08 09 16 09 8e 69 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 13 05 de 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

