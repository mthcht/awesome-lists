rule TrojanDownloader_MSIL_Mendokus_A_2147722010_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Mendokus.A"
        threat_id = "2147722010"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mendokus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 72 f1 02 00 70 fe 0c 02 00 28 17 00 00 06 72 55 00 00 70 28 0b 00 00 06 0a 06 72 21 03 00 70 fe 0c 02 00 28 17 00 00 06 6f 23 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_2 = {fe 0e 02 00 fe 0d 02 00 4a 0b 38 ?? ?? ff ff 02 02 72 ?? 00 00 70 fe 0c 03 00 28 17 00 00 06 28 09 00 00 06 72 ?? 00 00 70 fe 0c 03 00 28 17 00 00 06 28 1a 00 00 0a 28 08 00 00 06 39 ?? ?? 00 00 20 ?? 00 00 00 fe 0e 02 00 fe 0d 02 00 4a 0b 38 ?? ?? ff ff 38 ?? ?? 00 00 20 ?? 00 00 00 fe 0e 02 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

