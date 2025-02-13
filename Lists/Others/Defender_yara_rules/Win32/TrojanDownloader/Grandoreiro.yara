rule TrojanDownloader_Win32_Grandoreiro_ZY_2147908271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Grandoreiro.ZY"
        threat_id = "2147908271"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8b 00 0f b6 04 06 0f b6 14 1e 03 c2 25 ff 00 00 00 0f b6 14 06 8b c7 85 c0 74 ?? 83 e8 04 8b 00 48 85 c0 7c ?? 40 33 db 30 14 1f 43 48}  //weight: 10, accuracy: Low
        $x_10_3 = {0f b7 44 50 fe 03 c3 b9 ff 00 00 00 99 f7 f9 8b f2 3b 7d ec 7d 03 47 eb 05 bf 01 00 00 00 8b 45 ?? 0f b7 44 78 fe 33 f0 8b de 8d 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

