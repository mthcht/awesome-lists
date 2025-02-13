rule TrojanDownloader_MSIL_Saweoeq_A_2147705945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Saweoeq.A"
        threat_id = "2147705945"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Saweoeq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/fedorenko/install.ini" wide //weight: 1
        $x_1_2 = {00 54 45 4d 50 00 41 55 54 4f 52 55 4e 00 64 65 73 63 74 6f 70 00}  //weight: 1, accuracy: High
        $x_2_3 = {3a 00 2f 00 2f 00 73 00 34 00 76 00 65 00 2e 00 72 00 75 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 73 00 34 00 76 00 65 00 5f 00 61 00 64 00 73 00 ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

