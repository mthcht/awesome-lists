rule TrojanDownloader_Win32_Bloxxo_A_2147627321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bloxxo.A"
        threat_id = "2147627321"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bloxxo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 6a 00 81 ce 00 80 00 00 56 6a 00 e8 ?? ?? ?? ff eb 14 8b 07 e8 ?? ?? ?? ff 50 6a 00 6a 00 56 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = "6AF15381D91570EA2DD864FF" wide //weight: 1
        $x_1_3 = "7DDC74A929C2DA0946F26DD2013E9" wide //weight: 1
        $x_1_4 = "blomc202.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

