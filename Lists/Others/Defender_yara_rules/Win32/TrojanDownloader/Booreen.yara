rule TrojanDownloader_Win32_Booreen_A_2147597981_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Booreen.A"
        threat_id = "2147597981"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Booreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "firstwolf.org/rd/file.php?id=" ascii //weight: 1
        $x_1_2 = "burin.biz/rd/rd.php?id=" ascii //weight: 1
        $x_1_3 = "A25849C4-93F3-429D-FF34-260A2068897C" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_5 = "bensorty.dll" ascii //weight: 1
        $x_1_6 = "URLDownloadToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

