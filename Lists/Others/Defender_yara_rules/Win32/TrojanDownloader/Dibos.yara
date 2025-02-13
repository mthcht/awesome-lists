rule TrojanDownloader_Win32_Dibos_A_2147650660_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dibos.A"
        threat_id = "2147650660"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dibos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Scandisk\\" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\firewall" ascii //weight: 1
        $x_1_3 = "system.exe" ascii //weight: 1
        $x_1_4 = "dbs.dat" ascii //weight: 1
        $x_1_5 = ":*:Enabled:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

