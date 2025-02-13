rule TrojanDownloader_MSIL_Blocgree_A_2147719292_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Blocgree.A"
        threat_id = "2147719292"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocgree"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://5.206.225.17/blog/screen.php" wide //weight: 1
        $x_1_2 = "http://5.206.225.17/blog/w2eezcfue85y.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

