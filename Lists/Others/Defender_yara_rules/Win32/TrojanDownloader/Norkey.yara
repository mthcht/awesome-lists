rule TrojanDownloader_Win32_Norkey_A_2147684521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Norkey.A"
        threat_id = "2147684521"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Norkey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 51 01 41 84 d2 75 f8 a1 ?? ?? ?? ?? 66 8b 15 ?? ?? ?? ?? 89 01 a0 ?? ?? ?? ?? 66 89 51 04 88 41 06 85 f6 0f 84 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 8d 4c 24 ?? 51 56 ff 54 24 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 47 01 47 84 c0 75 f8 6a 00 b9 06 00 00 00 be ?? ?? ?? ?? 6a 00 f3 a5 6a 02 6a 00 6a 00 68 00 00 00 40 8d 84 24 c8 00 00 00 50 a4 ff 54 24 34 89 44 24 14 c7 44 24 18 28 23 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

