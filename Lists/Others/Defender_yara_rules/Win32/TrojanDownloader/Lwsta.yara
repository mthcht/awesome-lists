rule TrojanDownloader_Win32_Lwsta_2147615631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lwsta"
        threat_id = "2147615631"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lwsta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 61 70 6a 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 70 63 62 6f 6f 73 74 65 72 00 70 70 63 62 6f 6f 73 74 65 72 00 00 50 72 6f 6a 65 63 74 31}  //weight: 1, accuracy: High
        $x_1_3 = ".apartmentjackpot.com" wide //weight: 1
        $x_1_4 = "lwstats.com/ppcbpop" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

