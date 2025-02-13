rule TrojanDownloader_Win32_Lentrigy_A_2147697772_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lentrigy.A"
        threat_id = "2147697772"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lentrigy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 8a 0a 84 c9 75 f6 03 00 80 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 30 d0 8b 55 f4 88 04 ?? 89}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 54 24 04 8a 04 02 88 44 1e ff 39 df 7f d8}  //weight: 1, accuracy: High
        $x_1_4 = {ff 30 c1 8b 55 ?? 8b 45 ?? 88 0c 02}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 00 83 e8 ?? 8b 55 08 88 02 ff 45 08 8b 45 08 8a 00 84 c0 75 e6}  //weight: 1, accuracy: Low
        $x_1_6 = {ff 30 d0 8b ?? ?? ?? ff ff 8b ?? ?? ?? ff ff 88 04 11 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

