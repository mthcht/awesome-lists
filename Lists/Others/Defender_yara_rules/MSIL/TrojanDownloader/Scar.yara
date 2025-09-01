rule TrojanDownloader_MSIL_Scar_NIT_2147950974_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Scar.NIT!MTB"
        threat_id = "2147950974"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 f0 00 00 70 0a 72 81 01 00 70 0b 1d 28 ?? 00 00 0a 0c 08 07 28 ?? 00 00 0a 0d 73 17 00 00 0a 13 04 11 04 06 09 6f ?? 00 00 0a de 0c 11 04 2c 07 11 04 6f ?? 00 00 0a dc 09 28 ?? 00 00 0a 26 de 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

