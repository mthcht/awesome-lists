rule TrojanDownloader_Win32_Hegel_F_2147658299_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hegel.F"
        threat_id = "2147658299"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hegel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d fc 23 c1 8a 44 30 08 30 04 1f}  //weight: 1, accuracy: High
        $x_1_2 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_3 = {68 65 67 65 6c 69 61 6e 69 7a 65 2e 63 6f 6d [0-48] 2f 74 61 6b 69 32 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_4 = {68 69 64 3d 25 73 25 73 [0-16] 66 61 6b 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Hegel_G_2147682185_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hegel.G"
        threat_id = "2147682185"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hegel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 69 64 3d 25 73 25 73 [0-16] 26 73 74 61 74 75 73 3d 67 6f 6f 64}  //weight: 1, accuracy: Low
        $x_1_2 = {83 3f ff 74 08 81 fb 00 00 05 00 75 ?? ff 37 ff 15 ?? ?? ?? ?? 57 ff d6 59 81 fb 00 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

