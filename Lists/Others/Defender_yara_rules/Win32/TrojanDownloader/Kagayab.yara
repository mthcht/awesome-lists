rule TrojanDownloader_Win32_Kagayab_A_2147717891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kagayab.A"
        threat_id = "2147717891"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kagayab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 85 a4 fd ff ff 22 c6 85 a5 fd ff ff 3a c6 85 a6 fd ff ff 22 c6 85 a7 fd ff ff 42 c6 85 a8 fd ff ff 72 c6 85 a9 fd ff ff 61 c6 85 aa fd ff ff 7a c6 85 ab fd ff ff 69 c6 85 ac fd ff ff 6c}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 b7 fd ff ff 69 c6 85 b8 fd ff ff 70 c6 85 b9 fd ff ff 2d c6 85 ba fd ff ff 61 c6 85 bb fd ff ff 70 c6 85 bc fd ff ff 69 c6 85 bd fd ff ff 2e c6 85 be fd ff ff 63 c6 85 bf fd ff ff 6f c6 85 c0 fd ff ff 6d c6 85 c1 fd ff ff 2f}  //weight: 1, accuracy: High
        $x_1_3 = {c6 85 c8 fd ff ff 5c c6 85 c9 fd ff ff 73 c6 85 ca fd ff ff 63 c6 85 cb fd ff ff 70}  //weight: 1, accuracy: High
        $x_1_4 = {c6 85 b0 fd ff ff 43 c6 85 b1 fd ff ff 4c c6 85 b2 fd ff ff 53 c6 85 b3 fd ff ff 49 89 44 24 08 8d 85 b0 fd ff ff c6 85 b4 fd ff ff 44 c6 85 b5 fd ff ff 5c c6 85 b6 fd ff ff 25}  //weight: 1, accuracy: High
        $x_1_5 = {83 f1 08 88 4c 14 16 83 c2 01 83 fa 08 75 ec 66 85 f6 74 27 66 3b 78 12 74 2f 8d 4e ff 8d 50 20 0f b7 c9 6b c9 0e 8d 4c 08 20 eb 0b}  //weight: 1, accuracy: High
        $x_1_6 = {83 ec 14 85 c0 74 51 83 eb 01 75 c6 b8 05 00 00 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

