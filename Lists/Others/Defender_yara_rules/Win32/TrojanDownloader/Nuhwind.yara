rule TrojanDownloader_Win32_Nuhwind_A_2147596373_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nuhwind.A"
        threat_id = "2147596373"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuhwind"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "link1.m2a.co.kr/nhvwind/count3.php?MODE=1&" ascii //weight: 1
        $x_1_2 = "link1.m2a.co.kr/nhvwind/count3.php?MODE=3&" ascii //weight: 1
        $x_1_3 = "link1.m2a.co.kr/nhvwind/count3.php?MODE=5&" ascii //weight: 1
        $x_1_4 = "nhvinit.exe" ascii //weight: 1
        $x_1_5 = "nhvwindMain" ascii //weight: 1
        $x_1_6 = "nhvwind.exe" ascii //weight: 1
        $x_1_7 = "nhvinit00.exe" ascii //weight: 1
        $x_1_8 = "Software\\nhvwind" ascii //weight: 1
        $x_1_9 = "AdrMcMain" ascii //weight: 1
        $x_1_10 = "AdrMc.exe" ascii //weight: 1
        $x_1_11 = "URLDownloadToCacheFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

