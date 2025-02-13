rule TrojanDownloader_Win32_Wunkay_A_2147621370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wunkay.A"
        threat_id = "2147621370"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wunkay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 54 00 00 00 2b e1 8b fc 33 c0 f3 aa}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 74 0c 68 (40|e0) 00 e8 ?? 00 00 00 eb ?? 8d 85 ?? f9 ff ff 8d 95 ?? fb ff ff 6a 00 6a 00 50 52 6a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 43 f0 50 8d 43 ac 50 (33 d2 52 52 52 52 52|33 c0 b9 07 00 00 00 50)}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 95 d8 f9 ff ff 8d 43 f0 50 8d 43 ac 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 52 e8 dc 00 00 00 85 c0 74 0c 68 40 77 1b 00 e8 ec 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_6 = {00 07 47 e2 fb 68 ?? ?? 00 10 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 e8 ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

