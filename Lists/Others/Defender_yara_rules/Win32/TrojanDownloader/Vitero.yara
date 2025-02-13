rule TrojanDownloader_Win32_Vitero_A_2147627784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vitero.A"
        threat_id = "2147627784"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vitero"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".to.8866.org" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\" ascii //weight: 1
        $x_1_4 = "NtShutdownSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

