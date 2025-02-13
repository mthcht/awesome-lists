rule TrojanDownloader_MSIL_Crydap_A_2147709197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Crydap.A"
        threat_id = "2147709197"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crydap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PadC_Downloader.exe" wide //weight: 1
        $x_1_2 = "PadC_Downloader.Properties" ascii //weight: 1
        $x_1_3 = {24 39 63 38 66 65 37 32 61 2d 62 30 31 30 2d 34 61 30 61 2d 61 38 34 33 2d 39 30 34 32 30 38 32 31 62 33 62 62 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 50 72 6f 6a 65 63 74 73 5c 50 44 46 5c 50 61 64 43 5f 44 6f 77 6e 6c 6f 61 64 65 72 5c 62 69 6e 5c 44 65 62 75 67 5c 4f 62 66 75 73 63 61 74 65 64 5c 50 61 64 43 5f 44 6f 77 6e 6c 6f 61 64 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

