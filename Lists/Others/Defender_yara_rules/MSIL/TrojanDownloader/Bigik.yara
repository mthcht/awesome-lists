rule TrojanDownloader_MSIL_Bigik_A_2147651918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bigik.A"
        threat_id = "2147651918"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bigik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 65 74 5f 55 73 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 00 72 00 6f 00 70 00 62 00 6f 00 78 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 2f 00 [0-50] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "[autonrun]" wide //weight: 1
        $x_1_4 = "\\Pictures.scr" wide //weight: 1
        $x_1_5 = "\\autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

