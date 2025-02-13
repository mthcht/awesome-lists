rule TrojanDownloader_Win32_Seclogon_A_2147629028_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Seclogon.A"
        threat_id = "2147629028"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Seclogon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 2f 00 75 00 20 00 2f 00 73 00 20 00 22 00 25 00 73 00 22 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "{86A24C74-2BFC-4245-951B-8125AE0AD9AE}" wide //weight: 1
        $x_1_3 = {6a 00 8d 45 e4 50 8b 45 fc 89 45 ec c6 45 f0 11 8d 55 ec 33 c9 b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

