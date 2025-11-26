rule TrojanDownloader_Win32_KpotStealer_A_2147958302_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/KpotStealer.A!AMTB"
        threat_id = "2147958302"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "KpotStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://trynda.xyz/" ascii //weight: 3
        $x_3_2 = "http://193.135.12.107/file1.exe" ascii //weight: 3
        $x_1_3 = "shell32" ascii //weight: 1
        $x_1_4 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

