rule TrojanDownloader_MSIL_Winpact_A_2147721676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Winpact.A!bit"
        threat_id = "2147721676"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Winpact"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 53 1c 00 70 ?? 04 28 5e 00 00 0a 0a 17 03 28 5f 00 00 0a b5 13 04 0d 2b 25 ?? 06 03 09 17 28 60 00 00 0a 28 5e 00 00 0a 61 28 61 00 00 0a 28 62 00 00 0a 28 63 00 00 0a ?? 09 17 58 b5 0d 09 11 04 31 d6 ?? 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadFile" wide //weight: 1
        $x_1_3 = "Environ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

