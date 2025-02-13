rule TrojanDownloader_Win32_Ceysix_A_2147599410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ceysix.A"
        threat_id = "2147599410"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceysix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "svcs.exe" ascii //weight: 1
        $x_1_3 = "http://sey6.com/ver.php?no=" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "CreateServiceA" ascii //weight: 1
        $x_1_6 = "GetClipboardData" ascii //weight: 1
        $x_1_7 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_8 = "VirtualProtec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

