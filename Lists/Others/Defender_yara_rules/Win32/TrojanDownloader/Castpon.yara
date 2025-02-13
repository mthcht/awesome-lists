rule TrojanDownloader_Win32_Castpon_A_2147711065_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Castpon.A!bit"
        threat_id = "2147711065"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Castpon"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 4c 24 04 8b c1 83 f1 fe 35 f0 00 00 00 83 e1 0f 25 f0 0f 00 00 c1 e0 04 c1 f8 08 c1 e1 04 0b c1 c3 0f b6 4c 24 04 8b c1 83 e0 0f c1 e0 04 c1 e9 04 0b c1 35 fe 00 00 00 c3}  //weight: 2, accuracy: High
        $x_1_2 = {57 33 ff 39 7c 24 0c 7e 1c 56 8b 44 24 0c 8d 34 07 8a 04 07 50 e8 ?? ?? ?? ?? 47 59 3b 7c 24 10 88 06 7c e6 5e}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = {2d 64 65 6c 65 74 65 3d 00 00 00 2d 69 20 2d 61 64 64 3d 00 00 00 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

