rule TrojanDownloader_MSIL_Upatre_2147721960_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Upatre"
        threat_id = "2147721960"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 1f 00 00 0a ?? 6f 20 00 00 0a d8 19 d8 17 da 17 d6 8d 18 00 00 01}  //weight: 1, accuracy: Low
        $x_1_2 = {b7 17 da 11 04 da 02 11 04 91 ?? 61 ?? 11 04 ?? 8e b7 5d 91 61 9c 11 04 17 d6 13 04 11 04 11 05 31 db ?? 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

