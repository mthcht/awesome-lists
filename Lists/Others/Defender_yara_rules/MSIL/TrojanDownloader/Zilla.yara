rule TrojanDownloader_MSIL_Zilla_AR_2147957570_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Zilla.AR!MTB"
        threat_id = "2147957570"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_12_1 = {11 0b 16 14 16 13 1a 12 1a 16 16 13 1b 12 1b 16 6f}  //weight: 12, accuracy: High
        $x_8_2 = {16 fe 01 13 36 11 36 2c 19 11 34 11 0c 28 1c 01 00 06}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

