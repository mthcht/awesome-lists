rule TrojanDownloader_Win32_WinDots_2147799796_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/WinDots"
        threat_id = "2147799796"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "WinDots"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Software\\doublepoint" ascii //weight: 1
        $x_1_2 = "http://shop.doublepoint.net//install/uplist2.php?pid=" ascii //weight: 1
        $x_1_3 = "http://shop.doublepoint.net/install/p_boot.php" ascii //weight: 1
        $x_1_4 = "\\Software\\windots" ascii //weight: 1
        $x_1_5 = "dpup.dll" ascii //weight: 1
        $x_1_6 = "{900F4412-C5F4-4B5C-BF5D-F73D5D458B9B}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

