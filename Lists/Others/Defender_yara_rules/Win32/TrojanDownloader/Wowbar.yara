rule TrojanDownloader_Win32_Wowbar_F_2147596404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wowbar.F"
        threat_id = "2147596404"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowbar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 04 01 00 00 f3 ab 66 ab aa 8d [0-6] 89 1d ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8d [0-6] 89 1d ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 99 f7 3d ?? ?? ?? ?? bf ?? ?? ?? ?? 83 c9 ff 68 04 01 00 00 8b c2 89 15 ?? ?? ?? ?? c1 e0 06 03 c2 8d ?? ?? ?? ?? ?? ?? 33 c0 f2 ae f7 d1 2b f9 8b f7 8b e9 8b fa 83 c9 ff f2 ae 8b cd 4f c1 e9 02 f3 a5 8b cd 8d [0-6] 83 e1 03 50 f3 a4 e8 ?? ?? ?? ?? 6a 01 e8 ?? ?? ?? ?? 83 c4 18 85 c0 75 ?? 8d [0-6] 51 e8}  //weight: 10, accuracy: Low
        $x_1_2 = "http://comm.wowtoolbar.co.kr" ascii //weight: 1
        $x_1_3 = "BACKMAN" ascii //weight: 1
        $x_1_4 = "WT_GET_COMM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Wowbar_G_2147596678_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wowbar.G"
        threat_id = "2147596678"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowbar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 00 00 00 73 76 63 76 65 72}  //weight: 2, accuracy: High
        $x_2_2 = ".co.kr/version/svcver.php" ascii //weight: 2
        $x_2_3 = "/update.wowtoolbar.co.kr/" ascii //weight: 2
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

