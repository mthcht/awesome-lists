rule TrojanDownloader_Win32_Wesoten_A_2147614123_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wesoten.A"
        threat_id = "2147614123"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wesoten"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 75 fc bf 04 01 00 00 57 8d 85 a4 fc ff ff 50 ff 15 ?? ?? ?? ?? 68 98 05 40 00 8d 85 a4 fc ff ff 50 ff 15 ?? ?? ?? ?? 57 8d 85 b0 fd ff ff 50 56 8b 1d}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 85 1c f8 ff ff 50 ff 15 ?? ?? 40 00 68 20 bf 02 00 ff 15 ?? ?? 40 00 e9 b7 fd ff ff 83 a5 94 f6 ff ff 00 80 a5 d4 f6 ff ff 00 33 c0 8d bd d5 f6 ff ff ab}  //weight: 1, accuracy: Low
        $x_1_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 [0-64] 63 6d 64 20 2f 63 20 73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 30}  //weight: 1, accuracy: Low
        $x_1_4 = "%04d%02d%02d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

