rule TrojanDownloader_MSIL_Zegost_A_2147653794_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Zegost.A"
        threat_id = "2147653794"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "max1234" wide //weight: 1
        $x_1_2 = {66 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 61 00 31 00 32 00 33 00 34 00 2e 00 6d 00 69 00 72 00 65 00 65 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 2f 00 68 00 74 00 6d 00 6c 00 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "c:/windows/sys.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

