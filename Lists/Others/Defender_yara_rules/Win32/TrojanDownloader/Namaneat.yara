rule TrojanDownloader_Win32_Namaneat_A_2147709601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Namaneat.A"
        threat_id = "2147709601"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Namaneat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {30 04 39 80 34 39 3c 80 34 39 8c 80 34 39 7c 80 34 39 4c 41 81 f9 db 0a 00 00 75 e4}  //weight: 2, accuracy: High
        $x_2_2 = {eb 6e c7 85 28 fd ff ff 07 00 01 00 8d 85 28 fd ff ff 50 ff b5 d8 fc ff ff ff 93 29 19 00 10 85 c0 74 4d}  //weight: 2, accuracy: High
        $x_1_3 = "https://drive.google.com/file/d/" ascii //weight: 1
        $x_1_4 = "0B5xpJCkMMHu_VWw1VWFxQmdVNkU/view?pref=2&pli=1" ascii //weight: 1
        $x_1_5 = "%TEMP%" ascii //weight: 1
        $x_1_6 = "\\lpm.exe" ascii //weight: 1
        $x_1_7 = "/c.php?add=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

