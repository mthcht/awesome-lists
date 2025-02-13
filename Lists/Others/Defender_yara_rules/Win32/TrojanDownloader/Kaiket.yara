rule TrojanDownloader_Win32_Kaiket_A_2147596937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kaiket.A"
        threat_id = "2147596937"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kaiket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_2 = "pops.imgserver.kr/kai/install/install_count.php" ascii //weight: 1
        $x_1_3 = "pops.imgserver.kr/kai/install/update.php" ascii //weight: 1
        $x_1_4 = "software\\kai\\1\\livetime" ascii //weight: 1
        $x_1_5 = "block.intrich.com/block" ascii //weight: 1
        $x_1_6 = "kaiket.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

