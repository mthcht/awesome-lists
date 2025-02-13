rule TrojanDownloader_MSIL_NRatTiny_B_2147745184_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/NRatTiny.B!MSR"
        threat_id = "2147745184"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NRatTiny"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 4e 65 74 43 6c 69 65 6e 74 01 00 5c 4e 65 74 43 6c 69 65 6e 74 01 00 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4e 65 74 43 6c 69 65 6e 74 01 00 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_2_2 = {1a 28 10 00 00 0a 72 01 00 00 70 28 11 00 00 0a 80 04 00 00 04 7e 04 00 00 04 28 12 00 00 0a 26 1f 0a 8d 11 00 00 01 0a 12 00 28 02 00 00 06 06 0b 16 0c 2b 0c 07 08 9a 6f 13 00 00 0a 08 17}  //weight: 2, accuracy: High
        $x_2_3 = {04 0a 02 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 0b 0c 16 0d 2b 21 08 09 93 13 04 07 11 04 06 28 ?? ?? ?? ?? 13 05 12 05 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b 09 17 58 0d 09 08 8e 69 32 d9 07 2a}  //weight: 2, accuracy: Low
        $x_1_4 = {02 03 61 d1 10 00 02 2a ?? 02 28 ?? ?? ?? ?? 2a}  //weight: 1, accuracy: Low
        $x_1_5 = "AutxxRUN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

