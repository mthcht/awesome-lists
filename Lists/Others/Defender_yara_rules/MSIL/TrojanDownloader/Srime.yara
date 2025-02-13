rule TrojanDownloader_MSIL_Srime_A_2147719487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Srime.A!bit"
        threat_id = "2147719487"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Srime"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 6d 00 61 00 6e 00 33 00 33 00 2e 00 72 00 75 00 2f 00 [0-48] 2e 00 6a 00 70 00 67 00}  //weight: 10, accuracy: Low
        $x_1_2 = "&type=addlog&text=" wide //weight: 1
        $x_1_3 = "\\taskhostex.exe" wide //weight: 1
        $x_1_4 = "/taskhostew.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

