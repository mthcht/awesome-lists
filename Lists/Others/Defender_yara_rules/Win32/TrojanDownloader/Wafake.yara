rule TrojanDownloader_Win32_Wafake_A_2147916713_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wafake.A"
        threat_id = "2147916713"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wafake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 08 6a 01 e8 ?? ?? 01 00 83 c4 04 8d 4d 0c 51 6a 00 56 50 e8 72 ff ff ff ff 70 04 ff 30 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 33 c0 88 45 ff 8b e5 5d c3 cc cc cc 55 8b ec 51 33 c0 88 45 ff 8b e5 5d c3 cc cc cc 55 8b ec 51 33 c0 88 45 ff 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {4f 00 6c 00 65 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 4f 00 6c 00 65 00 41 00 75 00 74 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 53 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

