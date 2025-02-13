rule TrojanDownloader_MSIL_Bazidow_A_2147716103_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bazidow.A"
        threat_id = "2147716103"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bazidow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString(" wide //weight: 1
        $x_1_2 = "Bypass UAC" wide //weight: 1
        $x_1_3 = {49 00 6e 00 69 00 63 00 69 00 61 00 72 00 7b 00 [0-8] 7d 00 20 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 61 00 6f 00 64 00 20 00 6f 00 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = "/infects/index.php" wide //weight: 1
        $x_1_5 = "/brazil/bb.zip|http:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

