rule TrojanDownloader_MSIL_Vesad_A_2147705837_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Vesad.A"
        threat_id = "2147705837"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vesad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 34 76 65 5f 61 64 73 ?? 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {73 34 76 65 5f 61 64 73 ?? 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 30 5c 50 72 6f 6a 65 63 74 73 5c 73 34 76 65 5f 61 64 73 ?? 5c 73 34 76 65 5f 61 64 73 ?? 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 73 34 76 65 5f 61 64 73 ?? 2e 70 64 62 00}  //weight: 1, accuracy: Low
        $x_1_4 = {61 64 64 5f 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 43 6f 6d 70 6c 65 74 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

