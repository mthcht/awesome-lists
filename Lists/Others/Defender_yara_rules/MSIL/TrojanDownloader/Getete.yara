rule TrojanDownloader_MSIL_Getete_A_2147706184_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Getete.A"
        threat_id = "2147706184"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Getete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 65 00 2e 00 74 00 74 00 2f 00 61 00 70 00 69 00 2f 00 31 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-10] 2f 00 30 00 2f 00 62 00 6c 00 6f 00 62 00 3f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00}  //weight: 5, accuracy: Low
        $x_5_2 = "aHR0cDovL3NlcnYyLnNhbWF1cC5jb20vZmlsZX" wide //weight: 5
        $x_1_3 = {5c 64 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 ?? 5c 50 72 6f 6a 65 63 74 73 5c}  //weight: 1, accuracy: Low
        $x_1_4 = "\\Desktop\\tango\\tango\\" ascii //weight: 1
        $x_1_5 = "\\Desktop\\downloader\\downloader\\" ascii //weight: 1
        $x_1_6 = "\\Desktop\\project\\DllSer\\Service\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

