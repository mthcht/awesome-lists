rule TrojanDownloader_Win32_ScarletFlash_A_2147722047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ScarletFlash.A"
        threat_id = "2147722047"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "ScarletFlash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 1e 88 04 3e 88 0c 1e 0f b6 04 3e 8b 4d fc 03 c2 8b 55 f4 0f b6 c0 0f b6 04 ?? 30 04 11 41 89 4d fc 3b 4d f8 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f0 8b 4d e0 8b 55 e8 0f b6 00 03 45 f8 0f b6 c0 8a 04 03 30 04 0f 47 8b 45 f4 3b 7d ec 0f}  //weight: 1, accuracy: High
        $x_2_3 = {34 56 c4 fc 4b c2 12 9a 50 34 8a bc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

