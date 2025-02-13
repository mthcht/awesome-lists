rule TrojanDownloader_Win32_Perintal_A_2147650292_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Perintal.A"
        threat_id = "2147650292"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Perintal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://d2.3dprotect.net:90/update/?id=%d" wide //weight: 1
        $x_1_2 = {53 75 70 65 72 49 6e 73 74 61 6c 6c 32 00}  //weight: 1, accuracy: High
        $x_1_3 = {2d 00 30 00 39 00 33 00 36 00 42 00 37 00 38 00 42 00 31 00 30 00 42 00 32 00 7d 00 00 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 69 00 6e 00 69 00 00 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 7b 00 35 00 46 00 30 00 32 00 44 00 33 00 37 00 30 00 2d 00 32 00 45 00 39 00 43 00 2d 00 34 00 66 00 61 00 64 00 2d 00 39 00 43 00 46 00 31 00 2d 00 44 00 35 00 46 00 36 00 44 00 43 00 39 00 36 00 41 00 30 00 38 00 42 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {56 56 6a 01 8d 4c 24 24 51 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 08 b6 00 00 56 6a 04 8d 44 24 18 50 8d 54 24 2c 6a ff c7 44 24 20 0c 00 00 00 89 74 24 28 89 54 24 24 ff 15 ?? ?? ?? ?? a3 b4 28 45 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 3b ce 74 ?? 3d b7 00 00 00 75 ?? 89 35 b0 28 45 00 68 08 b6 00 00 56 56 68 1f 00 0f 00 51 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

