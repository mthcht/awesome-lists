rule TrojanDownloader_MSIL_Zusy_CCIG_2147913305_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Zusy.CCIG!MTB"
        threat_id = "2147913305"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 2b 17 02 07 8f ?? 00 00 01 25 49 06 07 06 8e 69 5d 93 61 d1 53 07 17 58 0b 07 02 8e 69 32 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

