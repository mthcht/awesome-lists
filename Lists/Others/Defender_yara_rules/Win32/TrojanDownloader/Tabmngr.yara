rule TrojanDownloader_Win32_Tabmngr_A_2147596320_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tabmngr.A"
        threat_id = "2147596320"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tabmngr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "nogaricast.com/police.php?luncher=%FOLDER" ascii //weight: 10
        $x_10_2 = "%DOMAIN%log-bin/lunch_load.php?aff_id=%AFFID&lunch_id=%LUNCHID&maddr=%MACADDR" ascii //weight: 10
        $x_10_3 = "%DOMAIN%log-bin/lunch_install.php?aff_id=%AFFID&lunch_id=%LUNCHID&maddr=%MACADDR&action=%ACTION" ascii //weight: 10
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_5 = "InternetReadFile" ascii //weight: 1
        $x_1_6 = "InternetCloseHandle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

