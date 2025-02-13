rule TrojanDownloader_MSIL_Bladabi_RS_2147899318_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabi.RS!MTB"
        threat_id = "2147899318"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 03 07 18 6f 03 00 00 0a 1f 10 28 04 00 00 0a 6f 05 00 00 0a 07 18 58 1d 2d 03 26 2b 03 0b 2b 00 07 03 6f 06 00 00 0a 32 d6 06 6f 07 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_2 = "41.216.183.235" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

