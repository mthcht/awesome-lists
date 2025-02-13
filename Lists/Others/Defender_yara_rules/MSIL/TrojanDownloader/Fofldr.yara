rule TrojanDownloader_MSIL_Fofldr_A_2147697345_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Fofldr.A"
        threat_id = "2147697345"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fofldr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Loades\\Loader" ascii //weight: 1
        $x_2_2 = "C:\\ProgramData\\ProtectedObject.cpl" wide //weight: 2
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6d 00 6f 00 75 00 73 00 65 00 2e 00 6e 00 65 00 74 00 2e 00 62 00 72 00 2f 00 63 00 6c 00 61 00 2f 00 [0-16] 2e 00 68 00 62 00 32 00}  //weight: 1, accuracy: Low
        $x_2_4 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-16] 2e 00 68 00 62 00 32 00}  //weight: 2, accuracy: Low
        $x_1_5 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 [0-32] 50 72 6f 63 65 73 73 [0-32] 48 69 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

