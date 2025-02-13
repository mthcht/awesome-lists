rule TrojanDownloader_Win32_Krado_A_2147681883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Krado.A"
        threat_id = "2147681883"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Krado"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ff 75 0c 8b 45 08 8d 88 00 20 00 00 51 (53|ff 75 ?? (??|?? ??)) ff 50 4c}  //weight: 1, accuracy: Low
        $x_1_2 = {50 ff 75 0c 8d (81|83) 00 20 00 00 50 (ff 75 ??|57) ff (51|53) 4c}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 5d 08 8d 83 00 20 00 00 50 ff 75 ?? ff 53 4c}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 00 08 00 8d (81|83|86|87|88) 00 20 00 00 (50|51) ff 75 ?? ff (50|51|53|56|57) 60}  //weight: 1, accuracy: Low
        $x_1_5 = {68 00 00 08 00 8d (81|83|86|87|88) 00 20 00 00 (50|51) [0-4] ff 75 ?? [0-10] ff (50|51|53|56|57) 60 85 c0 74 ?? 8b 45 ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 00 08 00 05 00 20 00 00 (50|51) ff 75 ?? [0-12] ff (50|51|53|56|57) 60 85 c0 74 ?? 8b 45 ?? 89 45}  //weight: 1, accuracy: Low
        $x_10_7 = {fa 65 00 78 00 03 00 c7 44 (41|42|43|46|47)}  //weight: 10, accuracy: Low
        $x_10_8 = {fe 65 00 00 00 03 00 c7 44 (41|43|46|47)}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

