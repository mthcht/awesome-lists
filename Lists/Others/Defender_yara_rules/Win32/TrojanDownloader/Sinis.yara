rule TrojanDownloader_Win32_Sinis_C_2147643937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sinis.C"
        threat_id = "2147643937"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Installation Aborted" ascii //weight: 4
        $x_2_2 = "\\messenger.exe" ascii //weight: 2
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "cryo-update.ca/" ascii //weight: 1
        $x_1_5 = "startaliance.info/" ascii //weight: 1
        $x_1_6 = "driverupdservers.net/" ascii //weight: 1
        $x_1_7 = "/cfg/crypt1.php?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

