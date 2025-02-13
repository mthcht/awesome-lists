rule TrojanDownloader_Win32_Funnet_A_2147601807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Funnet.A"
        threat_id = "2147601807"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Funnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dialer.dll" ascii //weight: 1
        $x_1_2 = "InetLoad.dll" ascii //weight: 1
        $x_1_3 = "w-w-w-dot-com.com/update/version.ini" ascii //weight: 1
        $x_1_4 = "temp\\_update.exe" ascii //weight: 1
        $x_1_5 = "nsExec.dll" ascii //weight: 1
        $x_1_6 = "FindNextFileA" ascii //weight: 1
        $x_1_7 = "CreateDirectoryA" ascii //weight: 1
        $x_1_8 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_9 = "SetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

