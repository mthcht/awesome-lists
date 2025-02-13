rule TrojanDownloader_Win32_Rcash_A_2147605519_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rcash.A"
        threat_id = "2147605519"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "r-cash.co.kr/update/distribute/rcashv2" ascii //weight: 1
        $x_1_3 = "RCashData.dll" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "gethostbyname" ascii //weight: 1
        $x_1_6 = "GetClipboardData" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

