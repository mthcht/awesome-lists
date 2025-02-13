rule TrojanDownloader_Win32_Discpy_A_2147686186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Discpy.A"
        threat_id = "2147686186"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Discpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 8b 55 ?? 8b 42 0c ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {03 55 0c 8b 5a 20 03 5d 0c 8b 4a 18 8b 33 03 75 0c 6a 00 56 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

