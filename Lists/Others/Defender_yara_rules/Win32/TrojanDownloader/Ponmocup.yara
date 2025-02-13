rule TrojanDownloader_Win32_Ponmocup_C_2147804220_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ponmocup.C"
        threat_id = "2147804220"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ponmocup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 f9 07 73 28 0f b6 c0 8b d0 d1 ea c1 e0 07 33 d0 33 c0 8a c2 88 45 b7 0f b7 f1 33 d2 8a 14 b5 ?? ?? ?? ?? 03 d0 88 54 35 cc 41 eb cf}  //weight: 1, accuracy: Low
        $x_1_2 = {75 f9 2b c2 8d bd fc fd ff ff 4f 8a 4f 01 47 84 c9 75 f8 8b c8 8b f2 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8d}  //weight: 1, accuracy: High
        $x_1_3 = {66 3d 39 00 73 20 81 c1 87 a9 f3 47 89 8d 9c fe ff ff 0f b7 f0 33 d2 8a 96 ?? ?? ?? ?? 2b d1 88 54 35 a8 40 eb d4}  //weight: 1, accuracy: Low
        $x_1_4 = {3a ca 7d 27 05 d7 3a ff ff 89 85 c8 fe ff ff 0f be f1 33 db 8a 1c 75 ?? ?? ?? ?? 33 d8 88 5c 35 d4 fe c1 88 8d cf fe ff ff eb d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

