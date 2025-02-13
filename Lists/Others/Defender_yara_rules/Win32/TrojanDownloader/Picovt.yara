rule TrojanDownloader_Win32_Picovt_A_2147680156_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Picovt.A"
        threat_id = "2147680156"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Picovt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 e8 00 00 00 00 8f 45 ?? 33 c0 66 8c c8 89 45 ?? 58}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d0 89 45 ?? c7 45 ?? 75 72 6c 6d c7 45 ?? 6f 6e 2e 64 66 c7 45 ?? 6c 6c c6 45 ?? 00 85 c0 74 ?? 8d 4d ?? 51 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

