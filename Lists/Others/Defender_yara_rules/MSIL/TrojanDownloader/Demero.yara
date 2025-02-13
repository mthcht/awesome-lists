rule TrojanDownloader_MSIL_Demero_A_2147679652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Demero.A"
        threat_id = "2147679652"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Demero"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 04 9a 6f 14 00 00 0a 00 00 de 05 26 00 00 de 00 00 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04 13 09 11 09 2d d7}  //weight: 1, accuracy: High
        $x_1_2 = {63 3a 5c 55 73 65 72 73 5c 45 6d 72 65 5c 44 65 73 6b 74 6f 70 5c [0-1] 45 78 74 65 6e 73 69 6f 6e 5c 44 6f 77 6e 6c 6f 61 64 65 72}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Installer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

