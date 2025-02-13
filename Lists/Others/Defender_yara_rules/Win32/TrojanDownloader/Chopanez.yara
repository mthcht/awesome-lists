rule TrojanDownloader_Win32_Chopanez_A_2147803770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chopanez.A"
        threat_id = "2147803770"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chopanez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "system32_xp_system_new" ascii //weight: 5
        $x_5_2 = "fuck off, buddy" ascii //weight: 5
        $x_5_3 = "c:\\_halt" ascii //weight: 5
        $x_5_4 = "C:\\TEMPinet200" ascii //weight: 5
        $x_5_5 = "127.0.0.1 download.mcafee.com liveupdate.symantecliveupdate.com liveupdate.symantec.com update.symantec.com" ascii //weight: 5
        $x_2_6 = "C:\\web.exe" ascii //weight: 2
        $x_2_7 = {83 c5 74 c9 c3 56 57 e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff be ?? ?? 40 00 56 33 ff e8 ?? ?? ff ff 85 c0 59 75 7c 53 e8 ?? ?? ff ff 6a 3c 33 d2 8b c7 59 f7 f1 85 d2 75 41 ff 35 ?? ?? 40 00 e8 ?? ?? ff ff 85 c0 59 75 31 ff 35 ?? ?? 40 00 e8 ?? ?? ff ff 85 c0 59 75 21 ff 35 ?? ?? 40 00 e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_8 = {53 b8 01 00 00 00 0f a2 f7 c2 00 00 80 00 0f 95 c0 0f b6 c0 a3 ?? ?? 40 00 5b c3}  //weight: 2, accuracy: Low
        $x_2_9 = {55 8b ec 83 ec 08 e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 68 ?? ?? 40 00 e8 ?? ?? ff ff 83 c4 04 85 c0 74 05 e9 ?? ?? 00 00 e8 ?? ?? ff ff 8b 45 fc 33 d2 b9 3c 00 00 00 f7 f1}  //weight: 2, accuracy: Low
        $x_2_10 = {55 8b ec 53 b8 01 00 00 00 0f a2 f7 c2 00 00 80 00 0f 95 c0 0f b6 c0 a3 ?? ?? 40 00 5b 5d c3}  //weight: 2, accuracy: Low
        $x_1_11 = "/affiliate/interface.php?userid=" ascii //weight: 1
        $x_1_12 = "&program=7&variable=check&value=" ascii //weight: 1
        $x_2_13 = "rxs.ini.php" ascii //weight: 2
        $x_1_14 = "/affcgi/online.fcgi?%ACCOUNT%" ascii //weight: 1
        $x_1_15 = "/mm.exe mmx" ascii //weight: 1
        $x_1_16 = "/mm2.exe mm2.exe %ACCOUNT%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

