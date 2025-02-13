rule TrojanDownloader_Win32_Eldycow_A_2147597318_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Eldycow.gen!A"
        threat_id = "2147597318"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Eldycow"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 8b 6c 24 24 81 7d 00 90 90 90 90 74 58 8b 45 00 8b 5d 04 b9 20 00 00 00 ba 20 37 ef c6}  //weight: 1, accuracy: High
        $x_1_2 = {e2 ee ff d3 5b 31 c0 c2 0c 00 60 8b 6c 24 24 8b 45 00 8b 5d 04 b9 20 00 00 00 ba 20 37 ef c6}  //weight: 1, accuracy: High
        $x_1_3 = {39 df 76 f2 5b c6 07 e9 89 57 01 50 54 6a 40 68 00 10 00 00 ff 75 08 ff 93 ?? ?? 00 00 59 09 c0 74 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

