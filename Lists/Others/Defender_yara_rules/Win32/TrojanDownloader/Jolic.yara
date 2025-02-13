rule TrojanDownloader_Win32_Jolic_A_2147646466_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Jolic.A"
        threat_id = "2147646466"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Jolic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 3c 23 0f 85 ?? ?? ?? ?? 33 c9 eb ?? ba 5b 5d 00 00 66 39 16}  //weight: 1, accuracy: Low
        $x_1_2 = {80 f9 30 7c ?? 80 f9 39 7f ?? 6b c0 0a 0f be c9 8d 44 08 d0 42 8a 0a 80 f9 20}  //weight: 1, accuracy: Low
        $x_1_3 = {50 8b c7 e8 ?? ?? ?? ?? 81 7d ?? 6a 6f 62 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

