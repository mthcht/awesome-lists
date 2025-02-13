rule TrojanDownloader_MSIL_Lidared_A_2147697351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lidared.A"
        threat_id = "2147697351"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lidared"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 70 00 68 00 70 00 3f 00 76 00 65 00 72 00 3d 00 90 00 02 00 0a 00 7b 00 31 00 7d 00 26 00 64 00 61 00 69 00 6c 00 69 00 3d 00 90 00 02 00 06 00 26 00 6d 00 61 00 63 00 3d 00 7b 00 33 00 7d 00 26 00 6d 00 69 00 64 00 3d 00 7b 00 34 00 7d 00 26 00 70 00 69 00 64 00 3d 00 7b 00 35 00 7d 00 26 00 64 00 69 00 64 00 3d 00 7b 00 36 00 7d 00 26 00 62 00 62 00 3d 00 32 00 36 00 35 00}  //weight: 1, accuracy: High
        $x_1_2 = "/add.php?id={1}&mac={3}" wide //weight: 1
        $x_1_3 = "/tongji.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

