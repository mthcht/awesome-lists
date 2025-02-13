rule TrojanDownloader_Win32_Ompiw_A_2147634218_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ompiw.A"
        threat_id = "2147634218"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ompiw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 46 0c 10 75 3d 56 68 80 05 00 00 8d 4c 24 18 6a 01 51 e8}  //weight: 1, accuracy: High
        $x_1_2 = {89 59 10 8a 5c 31 04 30 1c 38 8b 59 10 40 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

