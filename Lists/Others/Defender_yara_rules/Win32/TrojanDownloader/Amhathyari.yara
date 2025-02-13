rule TrojanDownloader_Win32_Amhathyari_A_2147601334_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Amhathyari.A"
        threat_id = "2147601334"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Amhathyari"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "soft.16990.com" ascii //weight: 1
        $x_1_3 = "svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_4 = "96C930FD-AE94-42D0-B638-6AF8C0930FCE" ascii //weight: 1
        $x_1_5 = "KavStart.exe" ascii //weight: 1
        $x_1_6 = "A24932FD-B707-44F6-BAF2-FEED49992EEE" ascii //weight: 1
        $x_1_7 = "MSDNSvc.dll" ascii //weight: 1
        $x_1_8 = "CreateServiceA" ascii //weight: 1
        $x_1_9 = "gethostbyname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

