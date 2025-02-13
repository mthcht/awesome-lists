rule TrojanDownloader_Win32_Zolpiq_E_2147645512_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zolpiq.E"
        threat_id = "2147645512"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zolpiq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 eb 05 8d 34 8b 2b ee 60 8b 7c 8b fc 29 2c 37 e2 f7 61 5d 03 c6 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {80 3b e9 74 0f 8b 44 24 14 c6 03 e9 2b c3 83 e8 05 89 43 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

