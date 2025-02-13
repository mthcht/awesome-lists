rule TrojanDownloader_Win32_Worfload_A_2147722893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Worfload.A!bit"
        threat_id = "2147722893"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Worfload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Inno Setup Messages" ascii //weight: 100
        $x_10_2 = "lapapahoster.com/download/exe/AdsShow_installer.exe" ascii //weight: 10
        $x_10_3 = "nihamatioto.com/download/exe/AdsShow_installer.exe" ascii //weight: 10
        $x_1_4 = "DOWNLOADANDEXECUTE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

