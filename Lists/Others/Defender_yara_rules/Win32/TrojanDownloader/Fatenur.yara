rule TrojanDownloader_Win32_Fatenur_A_2147647503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fatenur.A"
        threat_id = "2147647503"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fatenur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ftp.on.ufanet.ru>>%systemroot%/ff.bat" ascii //weight: 4
        $x_1_2 = "C:/isendsms_setup.exe" ascii //weight: 1
        $x_1_3 = "attrib +h %systemroot%/tasks/*.*" ascii //weight: 1
        $x_1_4 = "netsh advfirewall set currentprofile state off" ascii //weight: 1
        $x_1_5 = "sc config wscsvc start= disabled" ascii //weight: 1
        $x_1_6 = "sc start schedule" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

