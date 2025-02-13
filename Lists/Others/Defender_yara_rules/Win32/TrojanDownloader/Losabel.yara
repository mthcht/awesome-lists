rule TrojanDownloader_Win32_Losabel_B_2147598368_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Losabel.B"
        threat_id = "2147598368"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Losabel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 e4 33 c0 89 45 e8 89 45 e4 89 45 ec b8 ?? ?? ?? ?? e8 ?? ?? ff ff 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 e8 ?? ?? ff ff e8 ?? ?? ff ff 3c 01 75 ?? e8 ?? ?? ff ff c7 05 ?? ?? ?? ?? 02 00 00 00 8d 45 ec e8 ?? ?? ff ff 8b 55 ec b8 ?? ?? ?? ?? e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff 83 3d ?? ?? ?? ?? 03 75 ?? e8 ?? ?? ff ff 68 58 1b 00 00 e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff 6a ff 8d 45 e8 b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 45 e8 e8 ?? ?? ff ff 50 8d 55 e4 33 c0 e8 ?? ?? ff ff 8b 45 e4 e8 ?? ?? ff ff 50 e8 ?? ?? ff ff 68 88 13 00 00 e8 ?? ?? ff ff 33 c0 5a 59 59}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 fc 50 68 ?? ?? ?? ?? 68 02 00 00 80 e8 ?? ?? ff ff 8d 45 fc 50 68 ?? ?? ?? ?? 8b 45 fc 50 e8 ?? ?? ff ff 8d 45 fc 50 68 ?? ?? ?? ?? 8b 45 fc 50 e8 ?? ?? ff ff 8d 45 f8 b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 45 f8 e8 ?? ?? ff ff 68 ff 00 00 00 50 6a 01 6a 00 68 ?? ?? ?? ?? 8b 45 fc 50 e8 ?? ?? ff ff 33 c0 5a 59 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Losabel_H_2147624399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Losabel.H"
        threat_id = "2147624399"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Losabel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 40 77 1b 00 6a 00 6a 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 68 e8 03 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 16 85 c0 68 c8 00 00 00 e8 ?? ?? ff ff 6a 00 6a 00 6a 00 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 ff 13 6a 00}  //weight: 1, accuracy: Low
        $x_1_3 = "vistaA.exe" ascii //weight: 1
        $x_1_4 = "LoveHebe" ascii //weight: 1
        $x_1_5 = "ravmond.exe" ascii //weight: 1
        $x_1_6 = "360Safe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

