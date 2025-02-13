rule TrojanDownloader_Win32_Trosup_A_2147628689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Trosup.A"
        threat_id = "2147628689"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Trosup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a c2 b1 03 f6 e9 ?? ?? ?? ?? 00 04 32 83 c9 ff 33 c0 42 f2 ae f7 d1 49 3b d1 72 ?? 80 24 32 00 5f 5e c3}  //weight: 10, accuracy: Low
        $x_10_2 = {c9 c3 56 be ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? c7 04 24 4d 01 00 00 56 e8 ?? ?? ?? ?? 59 59 5e c3}  //weight: 10, accuracy: Low
        $x_1_3 = {25 73 25 64 [0-8] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 00 75 72 6c 6d 6f 6e 2e 64 6c 6c [0-16] 25 64 00 00 5c 55 73 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

