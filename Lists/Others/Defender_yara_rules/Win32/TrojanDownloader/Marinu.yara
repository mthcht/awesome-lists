rule TrojanDownloader_Win32_Marinu_B_2147679032_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Marinu.B"
        threat_id = "2147679032"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Marinu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/kfm/get.php?id=1912&forcedownload=1" ascii //weight: 1
        $x_1_2 = "/img/p6.jpg" ascii //weight: 1
        $x_1_3 = "/module/z5.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

