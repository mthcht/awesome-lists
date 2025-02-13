rule TrojanDownloader_MSIL_Liona_A_2147831846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Liona.A!MTB"
        threat_id = "2147831846"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Liona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 07 91 20 55 03 00 00 59 d2 9c 00 07 17 58 0b 07 7e ?? 00 00 04 8e 69 fe 04 0c 08 2d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

