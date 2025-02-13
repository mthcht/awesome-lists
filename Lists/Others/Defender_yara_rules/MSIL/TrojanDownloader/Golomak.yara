rule TrojanDownloader_MSIL_Golomak_A_2147697257_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Golomak.A"
        threat_id = "2147697257"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Golomak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 72 76 65 72 43 6f 6d 70 75 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 6f 77 6e 6c 6f 61 65 64 65 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 65 43 6f 4c 6f 47 79 5c 64 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 30 5c 50 72 6f 6a 65 63 74 73 5c 4d 61 6b 5c 4d 61 6b 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 4d 61 6b 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_5 = "directDownload=true" wide //weight: 1
        $x_1_6 = "\\xupaeu.exe" wide //weight: 1
        $x_1_7 = "Mak.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

