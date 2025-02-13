rule TrojanDownloader_Win32_Stasky_B_2147801628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stasky.B"
        threat_id = "2147801628"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stasky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f0 64 a3 00 00 00 00 89 65 e8 c7 45 fc 00 00 00 00 e4 02 c7 45 fc fe ff ff ff 32 c0}  //weight: 1, accuracy: High
        $x_1_2 = {84 c0 74 09 68 80 ee 36 00 ff d6 eb ee 68 60 ea 00 00 ff d6 eb e5}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 01 00 84 56 56 50 ?? e8 ?? ?? ?? ?? ff d0 8b ?? 3b ?? 74 ?? 8d 4d ?? 51 8d 55 ?? 52 8d 45 ?? 50 68 05 00 00 20}  //weight: 1, accuracy: Low
        $x_1_4 = {83 65 fc 00 e4 02 (c7 45 fc fe ff|83 4d) 32 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {84 c0 74 07 68 80 ee 36 00 eb 05 68 60 ea 00 00 (ff d6|ff 15 ?? ?? ?? ??) eb}  //weight: 1, accuracy: Low
        $x_1_6 = {c7 45 fc 00 00 00 00 e4 02 c7 45 fc fe ff ff ff 32 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

