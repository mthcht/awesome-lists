rule TrojanDownloader_MSIL_Exnet_MK_2147961571_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Exnet.MK!MTB"
        threat_id = "2147961571"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_25_1 = {73 1e 00 00 0a 13 0c 11 0c 11 0b 6f 1f 00 00 0a 13 0d 11 0d 28 03 00 00 06 13 0e 11 0e 28 20 00 00 0a 13 0f 11 0f 6f 21 00 00 0a 13 10 11 10 6f 22 00 00 0a 8e 69 3a 06 00 00 00 14 38 0e 00 00 00 17 8d 01 00 00 1b}  //weight: 25, accuracy: High
        $x_10_2 = "QYexvz3fLedAzC0a6A94+/XoU+Tm1rbyXjdG6G7rmkBEyv01hScSbuGZeEFNII8w" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

